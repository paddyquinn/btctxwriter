package main

import (
  "bufio"
  "fmt"
  "math/big"
  "os"
  "strings"
  "strconv"

  "github.com/btcsuite/btcd/btcec"
  "github.com/btcsuite/btcutil"
  "github.com/btcsuite/btcutil/base58"
  "github.com/paddyquinn/btctxwriter/serializer"
)

func main() {
  // Get private key from command line arguments and use it to generate the associated public key.
  b := new(big.Int)
  b.SetString(os.Args[1], 10)
  privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), b.Bytes())
  pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
  s := serializer.NewSerializer(privKey, pubKey)

  // Create the command line scanner and start the command prompt.
  scanner := bufio.NewScanner(os.Stdin)
  fmt.Print("$ ")

prompt:
  for scanner.Scan() {
    line := strings.Split(scanner.Text(), " ")
    if line[0] == "" {
      fmt.Print("$ ")
      continue
    }
    var serialization []byte
    switch line[0] {
    case "create":
      if len(line) != 9 {
        fmt.Print("usage: create <prev tx> <UTXO index> <sequence> <script sig> <gist> <address> <amount> <change>\n$ ")
        continue
      }
      index, _ := strconv.ParseUint(line[2], 10, 32)
      sequence, _ := strconv.ParseUint(line[3], 16, 32)
      in := &serializer.Input{PrevTx: line[1], Index: uint32(index), Sequence: uint32(sequence)}
      address := line[6]
      addressPubKeyHash := base58.Decode(address)[1:21]
      amount, _ := strconv.ParseUint(line[7], 10, 64)
      change, _ := strconv.ParseUint(line[8], 10, 64)
      serialization = s.CreateHTLC(
        line[4],
        in,
        &serializer.Output{Amount: amount, ScriptPubKey: serializer.P2SH([]byte(line[5]), addressPubKeyHash, pubKeyHash)},
        &serializer.Output{Amount: change, ScriptPubKey: serializer.P2PKH(pubKeyHash)})
    case "redeem":
      if len(line) != 8 {
        fmt.Print("usage: redeem <gist> <prev tx> <UTXO index> <sequence> <address> <refund address> <amount>\n$ ")
        continue
      }
      index, _ := strconv.ParseUint(line[3], 10, 32)
      sequence, _ := strconv.ParseUint(line[4], 16, 32)
      in := &serializer.Input{PrevTx: line[2], Index: uint32(index), Sequence: uint32(sequence)}
      address := line[5]
      addressPubKeyHash := base58.Decode(address)[1:21]
      refundAddress := line[5]
      refundAddressPubKeyHash := base58.Decode(refundAddress)[1:21]
      amount, _ := strconv.ParseUint(line[7], 10, 64)
      serialization = s.RedeemHTLC(
        []byte(line[1]),
        addressPubKeyHash,
        refundAddressPubKeyHash,
        in,
        &serializer.Output{Amount: amount, ScriptPubKey: serializer.P2PKH(pubKeyHash)},
      )
    case "quit":
      break prompt
    }
    fmt.Printf("%x\n$ ", serialization)
  }
}
