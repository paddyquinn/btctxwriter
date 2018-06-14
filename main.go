package main

import (
  "bytes"
  "crypto/sha256"
  "encoding/binary"
  "encoding/hex"
  "fmt"
  "math/big"
  "os"

  "github.com/roasbeef/btcd/btcec"
  "github.com/btcsuite/btcd/txscript"
  "github.com/btcsuite/btcutil"
)

func main() {
  b := new(big.Int)
  b.SetString(os.Args[1], 10)
  privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), b.Bytes())
  serializedScriptPubKey, _ := hex.DecodeString("76a9147cb9c22532e25baa608e93877fc1b67d7c11bda188ac")
  dataToSign := bytes.NewBuffer(serializeTx(pubKey, serializedScriptPubKey))
  serializedSigHash := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedSigHash, uint32(txscript.SigHashAll))
  dataToSign.Write(serializedSigHash)
  sha256Hash := sha256.Sum256(dataToSign.Bytes())
  doubleSHA256 := sha256.Sum256(sha256Hash[:])
  sig, _ := privKey.Sign(doubleSHA256[:])
  serializedSig := sig.Serialize()
  // TODO: comment add byte for sighash
  buffer := bytes.NewBuffer([]byte{byte(len(serializedSig)+1)})
  buffer.Write(serializedSig)
  buffer.WriteByte(byte(txscript.SigHashAll))
  serializedPubKey := pubKey.SerializeCompressed()
  buffer.WriteByte(byte(len(serializedPubKey)))
  buffer.Write(serializedPubKey)
  fmt.Printf("%x\n", serializeTx(pubKey, buffer.Bytes()))
  /*
  def redeem_transaction():
  print('to do')*/
}

func serializeTx(pubKey *btcec.PublicKey, serializedScriptSig []byte) []byte {
  // Serialize the transaction version as 4 little endian bytes.
  var version uint32 = 1
  serializedVersion := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedVersion, version)
  serializedTx := bytes.NewBuffer(serializedVersion)

  // Serialize the number of input UTXOs to be spent. In our case it is just 1.
  serializedNumInputs := []byte{1}
  serializedTx.Write(serializedNumInputs)

  // Serialize the UTXO that we will be spending from a previous transaction.
  serializedTx.Write(serializeInput(serializedScriptSig))

  // Serialize the number of output UTXOs to be created. In our case it is 2: 1 for the challenge and 1 as a change
  // address.
  serializedNumOutputs := []byte{2}
  serializedTx.Write(serializedNumOutputs)

  // TODO: write comment (total = 2800000)
  serializedTx.Write(serializeOutput(100000, p2sh(pubKey, pubKey)))

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
  prevTxHash := "c74f49c7452a535b269a4a91f77ebd77e3225fcff938828ab6ba1287e2d2f3f0"
  serializedPrevTxHash, _ := hex.DecodeString(prevTxHash)
  for i, j := 0, len(serializedPrevTxHash)-1; i < j; i, j = i+1, j-1 {
    serializedPrevTxHash[i], serializedPrevTxHash[j] = serializedPrevTxHash[j], serializedPrevTxHash[i]
  }
  serializedInput := bytes.NewBuffer(serializedPrevTxHash)

  // Serialize the index of the UTXO to spend from the previous transaction as 4 little endian bytes.
  var inputIndex uint32 = 1
  serializedInputIndex := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedInputIndex, inputIndex)
  serializedInput.Write(serializedInputIndex)

  // Serialize the length of the signature as a byte.
  // TODO: make note about assumption that length will be less than 0xfd
  serializedInput.WriteByte(byte(len(serializedScriptSig)))

  // Append the serialized script sig.
  serializedInput.Write(serializedScriptSig)

  // Serialize the sequence number as 4 little endian bytes.
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

  // TODO: make note about assumption that length will be less than 0xfd
  serializedOutput.WriteByte(byte(len(serializedScriptPubKey)))

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
  redeemScriptBuffer := bytes.NewBuffer([]byte{txscript.OP_HASH160})
  gist := []byte("https://gist.github.com/paddyquinn/be53db32330089c7b7ae5b7ce4353bbc")
  gistHash := btcutil.Hash160(gist)
  redeemScriptBuffer.WriteByte(byte(len(gistHash)))
  redeemScriptBuffer.Write(gistHash)
  redeemScriptBuffer.Write([]byte{txscript.OP_EQUAL, txscript.OP_IF})
  serializedPubKey := pubKey.SerializeCompressed()
  redeemScriptBuffer.WriteByte(byte(len(serializedPubKey)))
  redeemScriptBuffer.Write(serializedPubKey)
  redeemScriptBuffer.Write([]byte{txscript.OP_ELSE})
  //buffer.Write(timelock)
  redeemScriptBuffer.Write([]byte{txscript.OP_CHECKSEQUENCEVERIFY, txscript.OP_DROP})
  serializedRefundPubKey := refundPubKey.SerializeCompressed()
  redeemScriptBuffer.WriteByte(byte(len(serializedRefundPubKey)))
  redeemScriptBuffer.Write(serializedRefundPubKey)
  redeemScriptBuffer.Write([]byte{txscript.OP_ENDIF, txscript.OP_CHECKSIG})
  redeemScript := redeemScriptBuffer.Bytes()
  buffer := bytes.NewBuffer([]byte{txscript.OP_HASH160})
  buffer.WriteByte(byte(len(redeemScript)))
  buffer.Write(redeemScript)
  buffer.WriteByte(txscript.OP_EQUAL)
  return buffer.Bytes()
}
