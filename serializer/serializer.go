package serializer

import (
  "bytes"
  "crypto/sha256"
  "encoding/binary"
  "encoding/hex"

  "github.com/btcsuite/btcd/blockchain"
  "github.com/btcsuite/btcd/btcec"
  "github.com/btcsuite/btcd/txscript"
  "github.com/btcsuite/btcutil"
)

type Serializer struct {
  privKey *btcec.PrivateKey
  pubKey *btcec.PublicKey
}

func NewSerializer(privKey *btcec.PrivateKey, pubKey *btcec.PublicKey) *Serializer {
  return &Serializer{privKey: privKey, pubKey: pubKey}
}

func (s *Serializer) CreateHTLC(scriptPubKeyHex string, in *Input, outs ...*Output) []byte {
  // Serialize the previous scriptPubKey. This will be put in the place of the scriptSig for signing.
  serializedScriptPubKey, _ := hex.DecodeString(scriptPubKeyHex)

  // Sign the transaction with the given input.
  serializedSig := s.signTx(serializedScriptPubKey, in, outs...)

  // Create a bytes buffer with the first byte denoting the length of the signature. Note that 1 is added to the length
  // of the signature as the sighash will be appended to the signature.
  buffer := bytes.NewBuffer([]byte{byte(len(serializedSig)+1)})

  // Write the serialized signature and the sighash to the buffer.
  buffer.Write(serializedSig)
  buffer.WriteByte(byte(txscript.SigHashAll))

  // Write the serialized public key in compressed SEC format to the buffer.
  serializedPubKey := s.pubKey.SerializeCompressed()
  buffer.WriteByte(byte(len(serializedPubKey)))
  buffer.Write(serializedPubKey)

  // Serialize the transaction again with the signature as the scriptSig. In a fully fleshed out version of this
  // transaction writer the transaction would be stored as a struct and would not have to be completely reserialized.
  return s.serializeTx(buffer.Bytes(), in, outs...)
}

func (s *Serializer) RedeemHTLC(gist, addressPubKeyHash, refundPubKeyHash []byte, in *Input, out *Output) []byte {
  // Serialize the redeem script. This will be put in the place of the scriptSig for signing.
  redeemScript := redeemScript(gist, addressPubKeyHash, refundPubKeyHash)

  // Sign the transaction.
  serializedSig := s.signTx(redeemScript, in, out)

  // Create a bytes buffer with the first byte denoting the length of the signature. Note that 1 is added to the length
  // of the signature as the sighash will be appended to the signature.
  buffer := bytes.NewBuffer([]byte{byte(len(serializedSig)+1)})

  // Write the serialized signature and the sighash to the buffer.
  buffer.Write(serializedSig)
  buffer.WriteByte(byte(txscript.SigHashAll))

  // Write the serialized public key in compressed SEC format to the buffer.
  serializedPubKey := s.pubKey.SerializeCompressed()
  buffer.WriteByte(byte(len(serializedPubKey)))
  buffer.Write(serializedPubKey)

  // Write the gist to the buffer.
  buffer.Write(serializeScriptLength(len(gist)))
  buffer.Write(gist)

  // Write the redeem script to the buffer.
  buffer.Write(serializeScriptLength(len(redeemScript)))
  buffer.Write(redeemScript)

  // Serialize the transaction again with the signature and redeem script as the scriptSig. In a fully fleshed out
  // version of this transaction writer the transaction would be stored as a struct and would not have to be completely
  // reserialized.
  return s.serializeTx(buffer.Bytes(), in, out)
}

func (s *Serializer) signTx(serializedScriptPubKey []byte, in *Input, outs ...*Output) []byte{
  // Serialize the transaction with the previous scriptPubKey as the scriptSig.
  dataToSign := bytes.NewBuffer(s.serializeTx(serializedScriptPubKey, in, outs...))

  // Append the sighash to the transaction.
  serializedSigHash := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedSigHash, uint32(txscript.SigHashAll))
  dataToSign.Write(serializedSigHash)

  // Double SHA-256 the serialized transaction.
  sha256Hash := sha256.Sum256(dataToSign.Bytes())
  doubleSHA256 := sha256.Sum256(sha256Hash[:])

  // Sign the hashed transaction data and serialize the signature.
  sig, _ := s.privKey.Sign(doubleSHA256[:])
  return sig.Serialize()
}

func (s *Serializer) serializeTx(serializedScriptSig []byte, in *Input, outs ...*Output) []byte {
  // Serialize the transaction version as 4 little endian bytes.
  var version uint32 = 2
  serializedVersion := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedVersion, version)
  serializedTx := bytes.NewBuffer(serializedVersion)

  // Serialize the number of input UTXOs to be spent. In this case it is just 1.
  serializedNumInputs := []byte{1}
  serializedTx.Write(serializedNumInputs)

  // Serialize the UTXO that we will be spending from a previous transaction.
  serializedTx.Write(serializeInput(in, serializedScriptSig))

  // Serialize the number of output UTXOs to be created. In our case it is 2: 1 for the challenge and 1 as a change
  // address.
  serializedNumOutputs := []byte{byte(len(outs))}
  serializedTx.Write(serializedNumOutputs)

  // Serialize each passed output.
  for _, out := range outs {
    serializedTx.Write(serializeOutput(out.Amount, out.ScriptPubKey))
  }

  // Serialize the locktime as 4 little endian bytes. Use 0 so the transaction can be mined immediately.
  var locktime uint32 = 0
  serializedLocktime := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedLocktime, locktime)
  serializedTx.Write(serializedLocktime)

  return serializedTx.Bytes()
}

func serializeInput(in *Input, serializedScriptSig []byte) []byte {
  // Serialize the previous transaction hash as a little endian byte array.
  serializedPrevTxHash, _ := hex.DecodeString(in.PrevTx)
  for i, j := 0, len(serializedPrevTxHash)-1; i < j; i, j = i+1, j-1 {
    serializedPrevTxHash[i], serializedPrevTxHash[j] = serializedPrevTxHash[j], serializedPrevTxHash[i]
  }
  serializedInput := bytes.NewBuffer(serializedPrevTxHash)

  // Serialize the index of the UTXO to spend from the previous transaction as 4 little endian bytes.
  serializedInputIndex := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedInputIndex, in.Index)
  serializedInput.Write(serializedInputIndex)

  // Append the serialized script sig.
  serializedInput.Write(serializeVarint(len(serializedScriptSig)))
  serializedInput.Write(serializedScriptSig)

  // Serialize the sequence number as 4 little endian bytes.
  serializedSequence := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedSequence, in.Sequence)
  serializedInput.Write(serializedSequence)

  return serializedInput.Bytes()
}

func serializeOutput(amount uint64, serializedScriptPubKey []byte) []byte {
  // Serialize the amount as 8 little endian bytes.
  serializedAmount := make([]byte, 8)
  binary.LittleEndian.PutUint64(serializedAmount, amount)
  serializedOutput := bytes.NewBuffer(serializedAmount)

  // Append the scriptPubKey.
  serializedOutput.Write(serializeVarint(len(serializedScriptPubKey)))
  serializedOutput.Write(serializedScriptPubKey)

  return serializedOutput.Bytes()
}

func serializeScriptLength(length int) []byte {
  // If the length of the data will collide with an opcode, use the OP_PUSHDATA1 opcode to note that the next byte
  // represents a length rather than an opcode. Note that this only handles lengths that can be serialized in one byte.
  if length > 0x4b {
    return []byte{txscript.OP_PUSHDATA1, byte(length)}
  }
  return []byte{byte(length)}
}

func serializeVarint(length int) []byte {
  // If the length of the encoding cannot fit in one byte, prepend it with 0xfd and encode the length in two bytes. Note
  // that this only encodes varints below 0x10000, which is sufficient for this use case.
  if length >= 0xfd {
    buffer := bytes.NewBuffer([]byte{byte(0xfd)})
    serializedLength := make([]byte, 2)
    binary.LittleEndian.PutUint16(serializedLength, uint16(length))
    buffer.Write(serializedLength)
    return buffer.Bytes()
  }
  return []byte{byte(length)}
}

func P2PKH(pubKeyHash []byte) []byte {
  scriptPubKey := bytes.NewBuffer([]byte{txscript.OP_DUP, txscript.OP_HASH160, byte(len(pubKeyHash))})
  scriptPubKey.Write(pubKeyHash)
  scriptPubKey.Write([]byte{txscript.OP_EQUALVERIFY, txscript.OP_CHECKSIG})
  return scriptPubKey.Bytes()
}

func P2SH(gist, addressPubKeyHash, refundPubKeyHash []byte) []byte {
  // Create the redeemScript.
  redeemScript := redeemScript(gist, addressPubKeyHash, refundPubKeyHash)

  // Hash the redeem script.
  hashedRedeemScript := btcutil.Hash160(redeemScript)

  // Serialize a p2sh script, which is simply HASH160 <redeem script> EQUAL.
  buffer := bytes.NewBuffer([]byte{txscript.OP_HASH160})
  buffer.WriteByte(byte(len(hashedRedeemScript)))
  buffer.Write(hashedRedeemScript)
  buffer.WriteByte(txscript.OP_EQUAL)
  return buffer.Bytes()
}

func redeemScript(gist, addressPubKeyHash, refundPubKeyHash []byte) []byte {
  // Initialize the redeem script buffer with the Hash160 opcode.
  redeemScriptBuffer := bytes.NewBuffer([]byte{txscript.OP_HASH160})

  // Hash160 the gist and write it to the redeem script buffer.
  gistHash := btcutil.Hash160(gist)
  redeemScriptBuffer.WriteByte(byte(len(gistHash)))
  redeemScriptBuffer.Write(gistHash)

  // Write the equal and if op codes to the redeem script buffer. This means that if someone can produce the gist that
  // created the hash they can go down the if branch and redeem their bitcoin immediately.
  redeemScriptBuffer.Write([]byte{txscript.OP_EQUAL, txscript.OP_IF})

  // Write the p2pkh to the redeem script that is allowed to redeem the transaction immediately as long as the gist
  // is known.
  redeemScriptBuffer.Write(P2PKH(addressPubKeyHash))

  // Write the else opcode to the redeem script buffer, which will define the other branch of the if statement.
  redeemScriptBuffer.Write([]byte{txscript.OP_ELSE})

  // Write a 1 week timelock tot he redeem script buffer.
  timelock := blockchain.LockTimeToSequence(true, 60 * 60 * 24 * 7)
  serializedTimelock := make([]byte, 4)
  binary.BigEndian.PutUint32(serializedTimelock, timelock)
  redeemScriptBuffer.WriteByte(byte(4))
  redeemScriptBuffer.Write(serializedTimelock)

  // Write the CSV and drop opcodes to the redeem script buffer. This will check that the sequence number of the
  // spending transaction is greater than or equal to the timelock set above. Since the CSV op code acts as a no op if
  // successful, the top of the stack needs to be dropped.
  redeemScriptBuffer.Write([]byte{txscript.OP_CHECKSEQUENCEVERIFY, txscript.OP_DROP})

  // Write the p2pkh that is allowed to redeem this transaction after 1 week to the redeem script buffer.
  redeemScriptBuffer.Write(P2PKH(refundPubKeyHash))

  // Write the endif and checksig op codes to the buffer, which will end the branching logic above and check whichever
  // signature is present.
  redeemScriptBuffer.WriteByte(txscript.OP_ENDIF)
  return redeemScriptBuffer.Bytes()
}
