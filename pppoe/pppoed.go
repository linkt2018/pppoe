package pppoe

import (
	"encoding/binary"
	"errors"
)

type DCode byte

const CodePADI DCode = 0x09
const CodePADO DCode = 0x07
const CodePADR DCode = 0x19
const CodePADS DCode = 0x65

type TagType uint16

const TagTypeBasic = 0x0101
const TagTypeAcName = 0x0102
const TagTypeHostUniq = 0x0103
const TagTypeAcCookie = 0x0104

const PPPoEDBasicLen = 6

// Packet ethernet pppoe discovery packet
type PPPoED struct {
	VersionAndType byte
	Code           DCode
	SessionID      uint16
	AcName         string
	AcCookie       []byte
	HostUniq       []byte
}

func NewPPPoEDPacket(code DCode, sessionID uint16, acName string, hostUniq []byte, acCookie []byte) PPPoED {
	return PPPoED{
		VersionAndType: 0x11,
		Code:           code,
		SessionID:      sessionID,
		AcName:         acName,
		HostUniq:       hostUniq,
		AcCookie:       acCookie,
	}
}

func (p PPPoED) Encode() (bs []byte) {
	var tags []byte
	if len(p.AcName) > 0 {
		tags = append(tags, divideUint16IntoByteArray(TagTypeAcName)...)
		tags = append(tags, divideUint16IntoByteArray(uint16(len(p.AcName)))...)
		tags = append(tags, []byte(p.AcName)...)
	}
	tags = append(tags, divideUint16IntoByteArray(TagTypeBasic)...)
	tags = append(tags, divideUint16IntoByteArray(uint16(0))...)
	if len(p.AcCookie) > 0 {
		tags = append(tags, divideUint16IntoByteArray(TagTypeAcCookie)...)
		tags = append(tags, divideUint16IntoByteArray(uint16(len(p.AcCookie)))...)
		tags = append(tags, p.AcCookie...)
	}
	if len(p.HostUniq) > 0 {
		tags = append(tags, divideUint16IntoByteArray(TagTypeHostUniq)...)
		tags = append(tags, divideUint16IntoByteArray(uint16(len(p.HostUniq)))...)
		tags = append(tags, p.HostUniq...)
	}

	bs = append(bs, p.VersionAndType, byte(p.Code))
	bs = append(bs, divideUint16IntoByteArray(p.SessionID)...)
	bs = append(bs, divideUint16IntoByteArray(uint16(len(tags)))...)
	bs = append(bs, tags...)
	return
}

func divideUint16IntoByteArray(u uint16) []byte {
	return []byte{byte(u >> 8), byte(u)}
}
func divideUint32IntoByteArray(u uint32) []byte {
	return []byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)}
}

func DecodePPPoED(content []byte) (p PPPoED, err error) {
	if len(content) < PPPoEDBasicLen {
		err = errors.New("invalid content length")
		return
	}
	p.VersionAndType = content[0]
	p.Code = DCode(content[1])
	p.SessionID = binary.BigEndian.Uint16(content[2:4])
	pLen := binary.BigEndian.Uint16(content[4:6])
	if pLen == 0 {
		return
	}
	if len(content) < int(pLen)+PPPoEDBasicLen {
		err = errors.New("invalid payload length")
		return
	}
	payload := content[PPPoEDBasicLen:]
	for {
		if len(payload) == 0 {
			break
		}
		if len(payload) < 4 {
			err = errors.New("invalid tag length")
			return
		}
		tagType := binary.BigEndian.Uint16(payload[0:2])
		tLen := binary.BigEndian.Uint16(payload[2:4])
		if len(payload) < int(tLen)+4 {
			err = errors.New("invalid tag paload length")
			return
		}
		if tLen > 0 {
			tagPayload := payload[4 : 4+tLen]
			switch tagType {
			case TagTypeAcName:
				p.AcName = string(tagPayload)
			case TagTypeHostUniq:
				p.HostUniq = tagPayload
			case TagTypeAcCookie:
				p.AcCookie = tagPayload
			}
		}
		payload = payload[4+tLen:]
	}
	return
}
