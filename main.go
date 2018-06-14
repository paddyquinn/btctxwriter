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

// gist = 'https://gist.github.com/paddyquinn/7277b010eaad0035c436a398c4cf0d43'

func main() {
  b := new(big.Int)
  b.SetString(os.Args[1], 10)
  privateKey, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), b.Bytes())
  serializedScriptPubKey, _ := hex.DecodeString("76a9147cb9c22532e25baa608e93877fc1b67d7c11bda188ac")
  dataToSign := bytes.NewBuffer(serializeTx(publicKey, serializedScriptPubKey))
  serializedSigHash := make([]byte, 4)
  binary.LittleEndian.PutUint32(serializedSigHash, uint32(txscript.SigHashAll))
  dataToSign.Write(serializedSigHash)
  sha256Hash := sha256.Sum256(dataToSign.Bytes())
  doubleSHA256 := sha256.Sum256(sha256Hash[:])
  sig, _ := privateKey.Sign(doubleSHA256[:])
  serializedSig := sig.Serialize()
  // TODO: comment add byte for sighash
  buffer := bytes.NewBuffer([]byte{byte(len(serializedSig)+1)})
  buffer.Write(serializedSig)
  buffer.WriteByte(byte(txscript.SigHashAll))
  serializedPubKey := publicKey.SerializeCompressed()
  buffer.WriteByte(byte(len(serializedPubKey)))
  buffer.Write(serializedPubKey)
  fmt.Printf("%x\n", serializeTx(publicKey, buffer.Bytes()))
  /*
  def redeem_transaction():
  print('to do')*/
}

func serializeTx(publicKey *btcec.PublicKey, serializedScriptSig []byte) []byte {
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
  // TODO: make this 2
  serializedNumOutputs := []byte{1}
  serializedTx.Write(serializedNumOutputs)

  // TODO: serialize the challenge UTXO

  serializedTx.Write(serializeOutput(publicKey))

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

func serializeOutput(publicKey *btcec.PublicKey) []byte {
  // Serialize the amount of change as 8 little endian bytes.
  var change uint64 = 2800000
  serializedChange := make([]byte, 8)
  binary.LittleEndian.PutUint64(serializedChange, change)
  serializedOutput := bytes.NewBuffer(serializedChange)

  // Serialize a P2PKH script pubkey.
  scriptPubKey := p2pkh(publicKey)

  // TODO: make note about assumption that length will be less than 0xfd
  serializedOutput.WriteByte(byte(len(scriptPubKey)))

  serializedOutput.Write(scriptPubKey)

  return serializedOutput.Bytes()
}

// TODO: make a comment that this is unnecessary
func p2pkh(publicKey *btcec.PublicKey) []byte {
  buffer := new(bytes.Buffer)
  buffer.Write(btcutil.Hash160(publicKey.SerializeCompressed()))
  publicKeyHash := buffer.Bytes()
  scriptPubKey := []byte{txscript.OP_DUP, txscript.OP_HASH160, byte(len(publicKeyHash))}
  scriptPubKey = append(scriptPubKey, publicKeyHash...)
  return append(scriptPubKey, txscript.OP_EQUALVERIFY, txscript.OP_CHECKSIG)
}
