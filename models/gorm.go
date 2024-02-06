package models

import (
	"fmt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	GVA_DB *gorm.DB
)

func GormMysql() *gorm.DB {
	mysqlConfig := mysql.Config{
		DSN:                       "root:123456@tcp(127.0.0.1:3306)/breedingsheep?charset=utf8mb4&parseTime=True&loc=Local", // DSN data source name
		DefaultStringSize:         256,                                                                                      // string 类型字段的默认长度
		SkipInitializeWithVersion: false,                                                                                    // 根据版本自动配置
	}
	// 创建自定义的配置对象
	config := &gorm.Config{
		PrepareStmt: true,
		Logger:      logger.Default.LogMode(logger.Info), // 设置日志模式为Info，即打印SQL
	}
	if db, err := gorm.Open(mysql.New(mysqlConfig), config); err != nil {
		return nil
	} else {
		db.InstanceSet("gorm:table_options", "ENGINE=")
		sqlDB, _ := db.DB()
		sqlDB.SetMaxIdleConns(10)
		sqlDB.SetMaxOpenConns(100)
		fmt.Println("数据库初始化成功")
		return db
	}
}
