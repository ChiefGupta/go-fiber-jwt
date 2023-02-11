package initializers

import (
	"fmt"
	"log"
	"os"

	"github.com/ChiefGupta/go-fiber-postgres/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func ConnectDB(config *Config) {
	var err error

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Shanghai",
		config.DBHost, config.DBUserName, config.DBUserPassword, config.DBName, config.DBPort,
	)

	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database")
		os.Exit(1)
	}

	DB.Exec("CREATE EXTENSION IF NOT EXISTS \"UUID-OSSP\"")
	DB.Logger = logger.Default.LogMode(logger.Info)

	log.Println("Running Migrations")
	err = DB.AutoMigrate(&models.User{})
	if err != nil {
		log.Fatal("Migration Failed:  \n", err.Error())
		os.Exit(1)
	}

	log.Println("Connected successfully to database")
}
