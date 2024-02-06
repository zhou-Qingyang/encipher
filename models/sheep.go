package models

type Lamb struct {
	Id           int    `json:"id" form:"id" gorm:"column:id;primaryKey"`
	JuanSheHao   string `gorm:"column:juanshehao;"`
	DengJiErHao  string `gorm:"column:dengjierhao;"`
	XingBie      string `gorm:"column:xingbie;"`
	YueLing      string `gorm:"column:yueling;"`
	TiZhong      string `gorm:"column:tizhong;"`
	TiGao        string `gorm:"column:tigao;"`
	TiChang      string `gorm:"column:tichang;"`
	XiongWei     string `gorm:"column:xiongwei;"`
	XiognKuan    string `gorm:"column:xiognkuan;"`
	XiongShen    string `gorm:"column:xiongshen;"`
	GuanWei      string `gorm:"column:guanwei;"`
	TiXingWaiMao string `gorm:"column:tixingwaimao;"`
	BeiZhu       string `gorm:"column:beizhu;"`
	Father       string `gorm:"column:father;"`
	Mather       string `gorm:"column:mather;"`
}

// TableName Printer 表名
func (*Lamb) TableName() string {
	return "lamb"
}
