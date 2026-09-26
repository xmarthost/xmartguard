package captcha

import (
	"crypto/rand"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"math/big"
)

// digitFont is a 5x7 bitmap per digit (one byte per row, low 5 bits used).
var digitFont = [10][7]byte{
	{0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E}, // 0
	{0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E}, // 1
	{0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F}, // 2
	{0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E}, // 3
	{0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02}, // 4
	{0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E}, // 5
	{0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E}, // 6
	{0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08}, // 7
	{0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E}, // 8
	{0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C}, // 9
}

func rnd(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// RenderPNG draws digits with per-glyph rotation, scale and offset jitter,
// a wave distortion and noise, so simple OCR does not read it.
func RenderPNG(w io.Writer, digits string) error {
	const W, H = 260, 90
	img := image.NewRGBA(image.Rect(0, 0, W, H))
	bg := color.RGBA{0xf8, 0xfa, 0xfc, 0xff}
	for y := 0; y < H; y++ {
		for x := 0; x < W; x++ {
			img.Set(x, y, bg)
		}
	}
	// Background speckle.
	for i := 0; i < 700; i++ {
		c := uint8(150 + rnd(90))
		img.Set(rnd(W), rnd(H), color.RGBA{c, c, uint8(170 + rnd(80)), 0xff})
	}
	n := len(digits)
	step := float64(W-30) / float64(n)
	phase := float64(rnd(628)) / 100
	for i, ch := range digits {
		d := int(ch - '0')
		if d < 0 || d > 9 {
			continue
		}
		scale := 6.5 + float64(rnd(20))/10 // pixels per font cell
		angle := (float64(rnd(50)) - 25) * math.Pi / 180
		cx := 15 + step*float64(i) + step/2 + float64(rnd(8)-4)
		cy := H/2 + float64(rnd(14)-7)
		col := color.RGBA{uint8(20 + rnd(60)), uint8(30 + rnd(50)), uint8(80 + rnd(90)), 0xff}
		sin, cos := math.Sin(angle), math.Cos(angle)
		// Map each output pixel near the glyph back into font space.
		r := int(scale * 6)
		for py := int(cy) - r; py <= int(cy)+r; py++ {
			for px := int(cx) - r; px <= int(cx)+r; px++ {
				dx, dy := float64(px)-cx, float64(py)-cy
				fx := (dx*cos+dy*sin)/scale + 2.5
				fy := (-dx*sin+dy*cos)/scale + 3.5
				gx, gy := int(math.Floor(fx)), int(math.Floor(fy))
				if gx < 0 || gx > 4 || gy < 0 || gy > 6 {
					continue
				}
				if digitFont[d][gy]&(1<<(4-gx)) == 0 {
					continue
				}
				wy := py + int(3*math.Sin(float64(px)/14+phase))
				if px >= 0 && px < W && wy >= 0 && wy < H {
					img.Set(px, wy, col)
				}
			}
		}
	}
	// Crossing curves in the text colour range.
	for l := 0; l < 4; l++ {
		col := color.RGBA{uint8(40 + rnd(80)), uint8(40 + rnd(80)), uint8(90 + rnd(100)), 0xff}
		amp, freq, off := float64(8+rnd(18)), float64(20+rnd(30)), float64(rnd(H))
		for x := 0; x < W; x++ {
			y := int(off + amp*math.Sin(float64(x)/freq+float64(l)))
			if y >= 0 && y < H {
				img.Set(x, y, col)
				if y+1 < H {
					img.Set(x, y+1, col)
				}
			}
		}
	}
	return png.Encode(w, img)
}
