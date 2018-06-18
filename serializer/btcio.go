package serializer

type Input struct {
  PrevTx string
  Index uint32
  Sequence uint32
}

type Output struct {
  Amount uint64
  ScriptPubKey []byte
}