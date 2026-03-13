package hysteria2

import (
	"crypto/rand"
	"net"
	"os"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/sha3"
)

const (
	salamanderSaltLen      = 8
	salamanderFixedJunkLen = 32 // фиксированная длина junk — чтобы сервер мог её удалить
	ObfsTypeSalamander     = "salamander"
)

type SalamanderPacketConn struct {
	net.PacketConn
	password []byte
}

func NewSalamanderConn(conn net.PacketConn, password []byte) net.PacketConn {
	writer, isVectorised := bufio.CreateVectorisedPacketWriter(conn)
	if isVectorised {
		return &VectorisedSalamanderPacketConn{
			SalamanderPacketConn: SalamanderPacketConn{
				PacketConn: conn,
				password:   password,
			},
			writer: writer,
		}
	} else {
		return &SalamanderPacketConn{
			PacketConn: conn,
			password:   password,
		}
	}
}

// deriveKey — кастомный ключ на SHA3-256 с префиксом из переменной окружения
func deriveKey(password []byte, salt []byte) [32]byte {
	h := sha3.New256()

	// Префикс из переменной окружения ILYA_FUCK_RKN
	prefix := []byte(os.Getenv("ILYA_FUCK_RKN"))
	if len(prefix) == 0 {
		prefix = []byte("default_anti_rkn_prefix_2026_v1") // запасной вариант
	}

	h.Write(prefix)
	h.Write(salt)
	h.Write(password)

	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

func (s *SalamanderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	if err != nil {
		return
	}
	if n <= salamanderFixedJunkLen+salamanderSaltLen {
		return 0, nil, nil // слишком короткий — игнорируем
	}

	// Удаляем junk + salt
	key := deriveKey(s.password, p[salamanderFixedJunkLen:salamanderFixedJunkLen+salamanderSaltLen])

	// Деобфускация XOR
	for index, c := range p[salamanderFixedJunkLen+salamanderSaltLen : n] {
		p[index] = c ^ key[index%32]
	}

	// Сдвигаем payload в начало
	copy(p, p[salamanderFixedJunkLen+salamanderSaltLen:n])
	return n - salamanderFixedJunkLen - salamanderSaltLen, addr, nil
}

func (s *SalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buffer := buf.NewSize(len(p) + salamanderFixedJunkLen + salamanderSaltLen)
	defer buffer.Release()

	// Добавляем фиксированный junk
	junk := make([]byte, salamanderFixedJunkLen)
	_, _ = rand.Read(junk)
	buffer.Write(junk)

	// Добавляем случайную соль
	buffer.WriteRandom(salamanderSaltLen)

	// Ключ по junk + salt
	key := deriveKey(s.password, buffer.Bytes()[salamanderFixedJunkLen:])

	// XOR payload
	for index, c := range p {
		common.Must(buffer.WriteByte(c ^ key[index%32]))
	}

	_, err = s.PacketConn.WriteTo(buffer.Bytes(), addr)
	if err != nil {
		return
	}
	return len(p), nil
}

func (s *SalamanderPacketConn) Upstream() any {
	return s.PacketConn
}

// Vectorised версия — оставляем без junk (для простоты)
type VectorisedSalamanderPacketConn struct {
	SalamanderPacketConn
	writer N.VectorisedPacketWriter
}

func (s *VectorisedSalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buffer := buf.NewSize(salamanderSaltLen)
	buffer.WriteRandom(salamanderSaltLen)
	key := deriveKey(s.password, buffer.Bytes())
	for i := range p {
		p[i] ^= key[i%32]
	}
	err = s.writer.WriteVectorisedPacket([]*buf.Buffer{buffer, buf.As(p)}, M.SocksaddrFromNet(addr))
	if err != nil {
		return
	}
	return len(p), nil
}

func (s *VectorisedSalamanderPacketConn) WriteVectorisedPacket(buffers []*buf.Buffer, destination M.Socksaddr) error {
	header := buf.NewSize(salamanderSaltLen)
	defer header.Release()
	header.WriteRandom(salamanderSaltLen)
	key := deriveKey(s.password, header.Bytes())
	var bufferIndex int
	for _, buffer := range buffers {
		content := buffer.Bytes()
		for index, c := range content {
			content[bufferIndex+index] = c ^ key[bufferIndex+index%32]
		}
		bufferIndex += len(content)
	}
	return s.writer.WriteVectorisedPacket(append([]*buf.Buffer{header}, buffers...), destination)
}
