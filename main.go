package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path"
	"strings"
)

func ToNRGBA(c color.Color) color.NRGBA {
	return color.NRGBAModel.Convert(c).(color.NRGBA)
}

func GetPixels(img image.Image) []byte {
	bounds := img.Bounds()
	rgb := make([]byte, 0, bounds.Dx()*bounds.Dy()*3)

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := ToNRGBA(img.At(x, y))
			rgb = append(rgb, c.R, c.G, c.B)
		}
	}

	return rgb
}

type EncryptFunc func(payload []byte, passphrase []byte) []byte

func EncryptGCM(payload []byte, passphrase []byte) []byte {
	key := sha256.Sum256(passphrase)
	c, err := aes.NewCipher(key[:])
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	// drop none and tag, we don't care about decryption
	encrypted := gcm.Seal(nil, nonce, payload, nil)
	return encrypted[:len(encrypted)-16]
}

func EncryptECB(payload []byte, passphrase []byte) []byte {
	key := sha256.Sum256(passphrase)
	c, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}

	blockSize := c.BlockSize()
	encrypted := make([]byte, len(payload))

	for i := 0; i < len(payload); i += blockSize {
		c.Encrypt(encrypted[i:i+blockSize], payload[i:i+blockSize])
	}

	return encrypted
}

func NewImage(img image.Image, encrypted_rgb []byte) image.Image {
	bounds := img.Bounds()
	out := image.NewNRGBA(bounds)

	minX := bounds.Min.X
	minY := bounds.Min.Y
	width := bounds.Dx()
	height := bounds.Dy()

	if width*height*3 > len(encrypted_rgb) {
		fmt.Println(len(encrypted_rgb))
		fmt.Println(width * height * 3)
		panic("Pixels array size is to small!")
	}

	for y := minY; y < bounds.Max.Y; y++ {
		for x := minX; x < bounds.Max.X; x++ {
			idx := ((x - minX) + (y-minY)*width) * 3
			r := encrypted_rgb[idx]
			g := encrypted_rgb[idx+1]
			b := encrypted_rgb[idx+2]
			a := ToNRGBA(img.At(x, y)).A

			c := color.NRGBA{r, g, b, a}
			out.SetNRGBA(x, y, c)
		}
	}

	return out
}

func main() {
	inputPath := flag.String("in", "", "Input PNG file")
	passStr := flag.String("pass", "Winter2026!", "Passphrase used for encryption")
	flag.Parse()

	if *inputPath == "" || path.Ext(*inputPath) != ".png" {
		flag.Usage()
		os.Exit(1)
	}

	inputFile, err := os.Open(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	img, err := png.Decode(inputFile)
	rgb := GetPixels(img)

	passphrase := ([]byte)(*passStr)
	modes := map[string]EncryptFunc{
		"aes-gcm": EncryptGCM,
		"aes-ecb": EncryptECB,
	}

	for mode, encryptFunc := range modes {
		ext := path.Ext(*inputPath)
		outputPath := strings.TrimSuffix(*inputPath, ext)
		outputPath = outputPath + "-" + mode + ext

		encrypted := encryptFunc(rgb, passphrase)

		outputFile, err := os.Create(outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		newImg := NewImage(img, encrypted)
		png.Encode(outputFile, newImg)
		fmt.Printf("Created %s\n", outputPath)
	}

}
