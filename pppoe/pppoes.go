package pppoe

import (
	"encoding/binary"
	"errors"
)

type SCode byte

const SCodeSessionData SCode = 0x00

type P2PProtocol uint16

const (
	P2PLinkCtrlProtocol P2PProtocol = 0xc021
	P2PAuthProtocol     P2PProtocol = 0xc023
)

const PPPoESBasicLen = 6
const P2PProtocolBasicLen = 4
const LinkCtrlOptionBasicLen = 2

type PPPoES struct {
	VersionAndType  byte
	Code            SCode
	SessionID       uint16
	P2PProtocol     P2PProtocol
	LinkProtocol    LinkCtrlProtocol
	PwdAuthProtocol PwdAuthProtocol
}

func NewPPPoESLinkProtocolPacket(sessionID uint16, auth AuthProtocol, linkCode LinkCode, identifier byte, maxReceiveUint uint16, magicNumber uint32, pfc bool, acfc bool, cb CallbackOperation) PPPoES {
	return PPPoES{
		VersionAndType: 0x11,
		Code:           SCodeSessionData,
		P2PProtocol:    P2PLinkCtrlProtocol,
		SessionID:      sessionID,
		LinkProtocol: LinkCtrlProtocol{
			Code:                        linkCode,
			Identifier:                  identifier,
			AuthProtocol:                auth,
			MaxReceiveUint:              maxReceiveUint,
			MagicNumber:                 magicNumber,
			ProtocolFieldCompression:    pfc,
			AddressCtrlFieldCompression: acfc,
			CallbackOperation:           cb,
		},
	}
}

func (p PPPoES) Encode() (bs []byte) {
	var pd []byte
	pd = append(pd, divideUint16IntoByteArray(uint16(p.P2PProtocol))...)
	switch p.P2PProtocol {
	case P2PLinkCtrlProtocol:
		pd = append(pd,
			byte(p.LinkProtocol.Code),
			p.LinkProtocol.Identifier)
		var options []byte
		if p.LinkProtocol.MaxReceiveUint > 0 {
			options = append(options, byte(OptionMaxReceiveUint), 0x4)
			options = append(options, divideUint16IntoByteArray(p.LinkProtocol.MaxReceiveUint)...)
		}
		if p.LinkProtocol.MagicNumber > 0 {
			options = append(options, byte(OptionMagicNumber), 0x6)
			options = append(options, divideUint32IntoByteArray(p.LinkProtocol.MagicNumber)...)
		}
		if p.LinkProtocol.AuthProtocol > 0 {
			options = append(options, byte(OptionAuthProtocol), 0x4)
			options = append(options, divideUint16IntoByteArray(uint16(p.LinkProtocol.AuthProtocol))...)
		}
		if p.LinkProtocol.ProtocolFieldCompression {
			options = append(options, byte(OptionProtocolFieldCompression), 0x2)
		}
		if p.LinkProtocol.AddressCtrlFieldCompression {
			options = append(options, byte(OptionAddressAndControlFieldCompression), 0x2)
		}
		if p.LinkProtocol.CallbackOperation > 0 {
			options = append(options, byte(OptionCallback), 0x3, byte(p.LinkProtocol.CallbackOperation))
		}
		pd = append(pd, divideUint16IntoByteArray(uint16(len(options)+4))...)
		pd = append(pd, options...)
	case P2PAuthProtocol:
		pd = append(pd,
			p.PwdAuthProtocol.Code,
			p.PwdAuthProtocol.Identifier)
		var data []byte
		if len(p.PwdAuthProtocol.PeerID) > 0 {
			data = append(data, byte(len(p.PwdAuthProtocol.PeerID)))
			data = append(data, []byte(p.PwdAuthProtocol.PeerID)...)
		}
		if len(p.PwdAuthProtocol.Password) > 0 {
			data = append(data, byte(len(p.PwdAuthProtocol.Password)))
			data = append(data, []byte(p.PwdAuthProtocol.Password)...)
		}
		pd = append(pd, data...)
	}

	bs = append(bs, p.VersionAndType, byte(p.Code))
	bs = append(bs, divideUint16IntoByteArray(p.SessionID)...)
	bs = append(bs, divideUint16IntoByteArray(uint16(len(pd)))...)
	bs = append(bs, pd...)
	return
}

func DecodePPPoES(bs []byte) (p PPPoES, err error) {
	if len(bs) < PPPoESBasicLen {
		err = errors.New("invalid pppoes content length")
		return
	}
	p.VersionAndType = bs[0]
	p.Code = SCode(bs[1])
	p.SessionID = binary.BigEndian.Uint16(bs[2:4])
	pLen := binary.BigEndian.Uint16(bs[4:PPPoESBasicLen])
	if pLen == 0 {
		return
	}
	// p2p protocol
	payload := bs[PPPoESBasicLen:]
	if len(payload) < int(pLen) {
		err = errors.New("invalid pppoes payload length")
		return
	}
	p.P2PProtocol = P2PProtocol(binary.BigEndian.Uint16(payload[:2]))
	payload = payload[2:]
	if len(payload) < P2PProtocolBasicLen {
		err = errors.New("invalid protocol length")
		return
	}
	switch p.P2PProtocol {
	case P2PLinkCtrlProtocol:
		p.LinkProtocol, err = DecodeLinkCtrlProtocol(payload)
	case P2PAuthProtocol:
		p.PwdAuthProtocol, err = DecodePwdAuthProtocol(payload)
	}
	return
}
