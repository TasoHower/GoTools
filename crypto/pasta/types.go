package pasta

// Field 方程组的X Y
type Field [4]uint64

// Scalar 标量，如私钥
type Scalar [4]uint64

// Currency 金额
type Currency uint64

// TokenID mina上token编号
type TokenID uint64

// Nonce Nonce
type Nonce uint32

// GlobalSlot GlobalSlot
type GlobalSlot uint32

// Memo Memo
type Memo [34]uint8

// Tag Tag
type Tag [3]bool

// Point 椭圆曲线上的点
type Point struct {
	X Field
	Y Field
}

// Compressed 压缩后的公钥
type Compressed struct {
	X     Field
	IsOdd bool
}

// Keypair 公私钥对
type Keypair struct {
	PubKey Point
	PriKey Scalar
}

// Transaction mina交易
type Transaction struct {
	Fee         Currency   `json:"fee"`
	FeeToken    TokenID    `json:"feeToken"`
	FeePayerPk  Compressed `json:"feePayerPk"`
	Nonce       Nonce      `json:"nonce"`
	ValidUntil  GlobalSlot `json:"validUntil"`
	Memo        Memo       `json:"memo"`
	Tag         Tag        `json:"tag"`
	SourcePk    Compressed `json:"sourcePk"`
	ReceiverPk  Compressed `json:"receiverPk"`
	TokenID     TokenID    `json:"tokenID"`
	Amount      Currency   `json:"amount"`
	TokenLocked bool       `json:"tokenLocked"`
}

// TransactionRequest 签名请求参数，用json序列化
type TransactionRequest struct {
	Fee         Currency   `json:"fee"`
	FeeToken    TokenID    `json:"feeToken"`
	FeePayerPk  string     `json:"feePayerPk"`
	Nonce       Nonce      `json:"nonce"`
	ValidUntil  GlobalSlot `json:"validUntil"`
	Memo        string     `json:"memo"`
	SourcePk    string     `json:"sourcePk"`
	ReceiverPk  string     `json:"receiverPk"`
	TokenID     TokenID    `json:"tokenID"`
	Amount      Currency   `json:"amount"`
	TokenLocked bool       `json:"tokenLocked"`
	Delegation  bool       `json:"delegation"`
	NetworkID   uint8      `json:"networkID"`
}

// Signature 签名结果，(r,s)
type Signature struct {
	Rx Field
	S  Scalar
}
