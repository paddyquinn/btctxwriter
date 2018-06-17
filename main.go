package main

import (
  "bytes"
  "crypto/sha256"
  "encoding/binary"
  "encoding/hex"
  "fmt"
  "math/big"
  "os"

  "github.com/roasbeef/btcd/blockchain"
  "github.com/roasbeef/btcd/btcec"
  "github.com/btcsuite/btcd/txscript"
  "github.com/btcsuite/btcutil"
)

func main() {
  // Get private key from command line arguments and use it to generate the associated public key
  b := new(big.Int)
  b.SetString(os.Args[1], 10)
  privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), b.Bytes())

  // Serialize the previous scriptPubKey. This will be put in the place of the scriptSig for signing.
  // TODO: should be an argument
  serializedScriptPubKey, _ := hex.DecodeString("76a9147cb9c22532e25baa608e93877fc1b67d7c11bda188ac")

  // Serialize the transaction with the previous scriptPubKey as the scriptSig.
  dataToSign := bytes.NewBuffer(serializeTx(pubKey, serializedScriptPubKey))

  // Append the sighash to the transaction.
  serializedSigHash := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedSigHash, uint32(txscript.SigHashAll))
  dataToSign.Write(serializedSigHash)

  // Double SHA-256 the serialized transaction.
  sha256Hash := sha256.Sum256(dataToSign.Bytes())
  doubleSHA256 := sha256.Sum256(sha256Hash[:])

  // Sign the hashed transaction data and serialize the signature.
  sig, _ := privKey.Sign(doubleSHA256[:])
  serializedSig := sig.Serialize()

  // Create a bytes buffer with the first byte denoting the length of the signature. Note that 1 is added to the length
  // of the signature as the sighash will be appended to the signature.
  buffer := bytes.NewBuffer([]byte{byte(len(serializedSig)+1)})

  // Write the serialized signature and the sighash to the buffer.
  buffer.Write(serializedSig)
  buffer.WriteByte(byte(txscript.SigHashAll))

  // Write the serialized public key in compressed SEC format to the buffer.
  serializedPubKey := pubKey.SerializeCompressed()
  buffer.WriteByte(byte(len(serializedPubKey)))
  buffer.Write(serializedPubKey)

  // Serialize the transaction again with the signature as the scriptSig. In a fully fleshed out version of this
  // transaction writer the transaction would be stored as a struct and would not have to be completely reserialized.
  fmt.Printf("%x\n", serializeTx(pubKey, buffer.Bytes()))

  /*def redeem_transaction():
  print('to do')*/
}

func serializeTx(pubKey *btcec.PublicKey, serializedScriptSig []byte) []byte {
  // Serialize the transaction version as 4 little endian bytes.
  var version uint32 = 1
  serializedVersion := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedVersion, version)
  serializedTx := bytes.NewBuffer(serializedVersion)

  // Serialize the number of input UTXOs to be spent. In this case it is just 1.
  serializedNumInputs := []byte{1}
  serializedTx.Write(serializedNumInputs)

  // Serialize the UTXO that we will be spending from a previous transaction.
  serializedTx.Write(serializeInput(serializedScriptSig))

  // Serialize the number of output UTXOs to be created. In our case it is 2: 1 for the challenge and 1 as a change
  // address.
  serializedNumOutputs := []byte{2}
  serializedTx.Write(serializedNumOutputs)

  // Serialize one output to a p2sh HTLC locked by a hash of this gist.
  serializedTx.Write(serializeOutput(100000, p2sh(pubKey, pubKey)))

  // Serialize a second output back to the original public key as change.
  serializedTx.Write(serializeOutput(2600000, p2pkh(pubKey)))

  // Serialize the locktime as 4 little endian bytes. Use 0 so the transaction can be mined immediately.
  var locktime uint32 = 0
  serializedLocktime := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedLocktime, locktime)
  serializedTx.Write(serializedLocktime)

  return serializedTx.Bytes()
}

func serializeInput(serializedScriptSig []byte) []byte {
  // Serialize the previous transaction hash as a little endian byte array.
  // TODO: should be an argument
  prevTxHash := "1c087b4a606e5395fc1d96cfddbdd9190eb486accfd196426c36fa438a229eea"
  serializedPrevTxHash, _ := hex.DecodeString(prevTxHash)
  for i, j := 0, len(serializedPrevTxHash)-1; i < j; i, j = i+1, j-1 {
    serializedPrevTxHash[i], serializedPrevTxHash[j] = serializedPrevTxHash[j], serializedPrevTxHash[i]
  }
  serializedInput := bytes.NewBuffer(serializedPrevTxHash)

  // Serialize the index of the UTXO to spend from the previous transaction as 4 little endian bytes.
  // TODO: should be an argument
  var inputIndex uint32 = 0
  serializedInputIndex := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedInputIndex, inputIndex)
  serializedInput.Write(serializedInputIndex)

  // Serialize the length of the signature as a byte. This should be serialized as a varint but for now is just
  // serialized as one byte for simplicity. The assumption is that the length of the signature in this case is less than
  // 0xfd, which can be represented by one byte.
  serializedInput.WriteByte(byte(len(serializedScriptSig)))

  // Append the serialized script sig.
  serializedInput.Write(serializedScriptSig)

  // Serialize the sequence number as 4 little endian bytes.
  // TODO: should be an argument
  var sequence uint32 = 0xffffffff
  serializedSequence := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedSequence, sequence)
  serializedInput.Write(serializedSequence)

  return serializedInput.Bytes()
}

func serializeOutput(amount uint64, serializedScriptPubKey []byte) []byte {
  // Serialize the amount as 8 little endian bytes.
  serializedAmount := make([]byte, 8)
  binary.LittleEndian.PutUint64(serializedAmount, amount)
  serializedOutput := bytes.NewBuffer(serializedAmount)

  // Serialize the length of the scriptPubKey as a byte. This should be serialized as a varint but for now is just
  // serialized as one byte for simplicity. The assumption is that the length of the scriptPubKey in this case is less
  // than 0xfd, which can be represented by one byte.
  serializedOutput.WriteByte(byte(len(serializedScriptPubKey)))

  // Append the scriptPubKey.
  serializedOutput.Write(serializedScriptPubKey)

  return serializedOutput.Bytes()
}

// TODO: make a comment that this is unnecessary; may not be if we have to send a tx to the purse public key
func p2pkh(pubKey *btcec.PublicKey) []byte {
  buffer := new(bytes.Buffer)
  buffer.Write(btcutil.Hash160(pubKey.SerializeCompressed()))
  pubKeyHash := buffer.Bytes()
  scriptPubKey := []byte{txscript.OP_DUP, txscript.OP_HASH160, byte(len(pubKeyHash))}
  scriptPubKey = append(scriptPubKey, pubKeyHash...)
  return append(scriptPubKey, txscript.OP_EQUALVERIFY, txscript.OP_CHECKSIG)
}

func p2sh(pubKey *btcec.PublicKey, refundPubKey *btcec.PublicKey) []byte {
  // Initialize the redeem script buffer with the Hash160 opcode.
  redeemScriptBuffer := bytes.NewBuffer([]byte{txscript.OP_HASH160})

  // Hash160 the gist and write it to the redeem script buffer.
  gist := []byte("https://gist.github.com/paddyquinn/be53db32330089c7b7ae5b7ce4353bbc")
  gistHash := btcutil.Hash160(gist)
  redeemScriptBuffer.WriteByte(byte(len(gistHash)))
  redeemScriptBuffer.Write(gistHash)

  // Write the equal and if op codes to the redeem script buffer. This means that if someone can produce the gist that
  // created the hash they can go down the if branch and redeem their bitcoin immediately.
  redeemScriptBuffer.Write([]byte{txscript.OP_EQUAL, txscript.OP_IF})

  // Write the pubkey to the redeem script that is allowed to redeem the transaction immediately as long as the gist
  // hash is known.
  serializedPubKey := pubKey.SerializeCompressed()
  redeemScriptBuffer.WriteByte(byte(len(serializedPubKey)))
  redeemScriptBuffer.Write(serializedPubKey)

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

  // Write the pubkey that is allowed to redeem this transaction after 1 week to the redeem script buffer.
  serializedRefundPubKey := refundPubKey.SerializeCompressed()
  redeemScriptBuffer.WriteByte(byte(len(serializedRefundPubKey)))
  redeemScriptBuffer.Write(serializedRefundPubKey)

  // Write the endif and checksig op codes to the buffer, which will end the branching logic above and check whichever
  // signature is present.
  redeemScriptBuffer.Write([]byte{txscript.OP_ENDIF, txscript.OP_CHECKSIG})
  redeemScript := redeemScriptBuffer.Bytes()

  // Hash the redeem script.
  hashedRedeemScript := btcutil.Hash160(redeemScript)

  // Serialize a p2sh script, which is simply HASH160 <redeem script> EQUAL.
  buffer := bytes.NewBuffer([]byte{txscript.OP_HASH160})
  buffer.WriteByte(byte(len(hashedRedeemScript)))
  buffer.Write(hashedRedeemScript)
  buffer.WriteByte(txscript.OP_EQUAL)
  return buffer.Bytes()
}
