package main

import (
	"bufio"
	"encryptor/signhelper"
	"fmt"
	"github.com/joho/godotenv"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file:", err)
		return
	}
	// Replace "SECRET_KEY" with the actual name of your environment variable
	secretKey := os.Getenv("VECTOR")

	// Check if the environment variable exists
	if secretKey == "" {
		fmt.Println("SECRET_KEY environment variable not found.")
		return
	}

	// Split the value using a comma as the delimiter
	keys := strings.Split(secretKey, ",")

	// Ensure that there are at least two parts after splitting
	if len(keys) < 2 {
		fmt.Println("SECRET_KEY value does not contain two parts separated by a comma.")
		return
	}

	// The first part is the secret key, and the second part is the IV key
	key := keys[0]
	iv := keys[1]
	reader := bufio.NewReader(os.Stdin)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGINT)
	defer func() {
		fmt.Println("\nExiting...")
	}()
	for {
		select {
		case <-sigCh:
			return
		default:
			fmt.Print("Enter the plain text (Ctrl+C to exit): ")
			plainText, _ := reader.ReadString('\n')
			plainText = strings.TrimSpace(plainText)
			fmt.Println("This is the original:", plainText)

			encrypted, err := signhelper.GetAESEncrypted(plainText, key, iv)
			if err != nil {
				fmt.Println("Error during encryption", err)
				return
			}

			fmt.Println("This is encrypted:", encrypted)

			decrypted, err := signhelper.GetAESDecrypted(encrypted, key, iv)
			if err != nil {
				fmt.Println("Error during decryption", err)
				return
			}

			fmt.Println("This is decrypted:", string(decrypted))
		}
	}
}
