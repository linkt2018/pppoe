package pppoe

import (
	"encoding/binary"
	"errors"
)

type PwdAuthProtocol struct {
	Code       byte
	Identifier byte
	PeerID     string
	Password   string
}

func (p PwdAuthProtocol) GetShowCode() string {
	switch p.Code {
	case 0x1:
		return "Auth request"
	}
	return "unknown"
}

func DecodePwdAuthProtocol(payload []byte) (p PwdAuthProtocol, err error) {
	p.Code = payload[0]
	p.Identifier = payload[1]
	authLen := binary.BigEndian.Uint16(payload[2:4])
	if authLen == 0 {
		return
	}
	payload = payload[P2PProtocolBasicLen:]
	if len(payload) < int(authLen)-P2PProtocolBasicLen {
		err = errors.New("invalid password auth data length")
		return
	}
	peerIDLen := payload[0]
	if peerIDLen < 1 {
		return
	}
	if len(payload) < int(peerIDLen)+1 {
		err = errors.New("invalid peer id data length")
		return
	}
	p.PeerID = string(payload[1 : peerIDLen+1])

	if len(payload) < int(peerIDLen)+2 {
		return
	}
	payload = payload[peerIDLen+1:]

	pwdLen := payload[0]
	if pwdLen < 1 {
		return
	}
	if len(payload) < int(pwdLen)+1 {
		err = errors.New("invalid pwd data length")
		return
	}
	p.Password = string(payload[1 : pwdLen+1])

	return
}
