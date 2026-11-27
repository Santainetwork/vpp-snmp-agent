package agentx

import (
 "encoding/binary"
 "fmt"
 "strings"
)

const (
 TYPE_INTEGER uint16 = 2
 TYPE_OCTETSTRING uint16 = 4
 TYPE_NULL uint16 = 5
 TYPE_OBJECTIDENTIFIER uint16 = 6
 TYPE_COUNTER32 uint16 = 65
 TYPE_GAUGE32 uint16 = 66
 TYPE_TIMETICKS uint16 = 67
 TYPE_COUNTER64 uint16 = 70
 TYPE_NOSUCHOBJECT uint16 = 128
 TYPE_NOSUCHINSTANCE uint16 = 129
 TYPE_ENDOFMIBVIEW uint16 = 130
 TYPE_IPADDRESS uint16 =  ipAddressType
)
const ipAddressType uint16 = 64
const ( ERROR_NOAGENTXERROR uint16 = 0; ERROR_GENERR uint16 = 5; ERROR_NOACCESS uint16 = 6; ERROR_WRONGTYPE uint16 = 7; ERROR_WRONGLENGTH uint16 = 8; ERROR_WRONGENCODING uint16 = 9; ERROR_WRONGVALUE uint16 = 10; ERROR_NOCREATION uint16 = 11; ERROR_INCONSISTENTVALUE uint16 = 12; ERROR_RESOURCEUNAVAILABLE uint16 = 13; ERROR_COMMITFAILED uint16 = 14; ERROR_UNDOFAILED uint16 = 15; ERROR_NOTWRITABLE uint16 = 17; ERROR_INCONSISTENTNAME uint16 = 18; ERROR_OPENFAILED uint16 = 256; ERROR_NOTOPEN uint16 = 257; ERROR_INDEXWRONGTYPE uint16 = 258; ERROR_INDEXALREADYALLOCATED uint16 = 259; ERROR_INDEXNONEAVAILABLE uint16 = 260; ERROR_INDEXNOTALLOCATED uint16 = 261; ERROR_UNSUPPORTEDCONTEXT uint16 = 262; ERROR_DUPLICATEREGISTRATION uint16 = 263; ERROR_UNKNOWNREGISTRATION uint16 = 264; ERROR_UNKNOWNAGENTCAPS uint16 = 265; ERROR_PARSEERROR uint16 = 266; ERROR_REQUESTDENIED uint16 = 267; ERROR_PROCESSINGERROR uint16 = 268 )
const ( PDU_OPEN uint32=1; PDU_REGISTER uint32=3; PDU_GET uint32=5; PDU_GETNEXT uint32=6; PDU_CLOSE uint32=2; PDU_PING uint32=13; PDU_RESPONSE uint32=18 )
type VarBind struct { Type uint16; Name string; Value any }
type SearchRange struct { StartOID, EndOID string; Include bool }
type PDU struct { Type, SessionID, TransactionID, PacketID uint32; Error, ErrorIndex uint16; Values []VarBind; RangeList []SearchRange; OID string }
func oidEncode(s string, include bool) []byte { parts:=strings.Split(strings.Trim(s,"."),"."); ids:=make([]uint32,0,len(parts)); for _,p:=range parts { var n uint32; fmt.Sscan(p,&n); ids=append(ids,n) }; prefix:=uint8(0); if len(ids)>5&&ids[0]==1&&ids[1]==3&&ids[2]==6&&ids[3]==1 { prefix=uint8(ids[4]); ids=ids[5:] }; b:=[]byte{byte(len(ids)),prefix,0,0}; if include {b[2]=1}; for _,n:=range ids { var x[4]byte; binary.BigEndian.PutUint32(x[:],n); b=append(b,x[:]...) }; return b }
func octetEncode(s string) []byte { b:=make([]byte,4+len([]byte(s))); binary.BigEndian.PutUint32(b,uint32(len([]byte(s)))); copy(b[4:],s); return append(b,make([]byte,(4-len(s)%4)%4)...)}
func (p PDU) Encode() []byte { var payload []byte; switch p.Type { case PDU_OPEN: payload=append(payload,5,0,0,0,0,0,0,0); payload=append(payload,octetEncode("MyAgent")...); case PDU_REGISTER: payload=append(payload,5,127,0,0); payload=append(payload,oidEncode(p.OID,false)...); case PDU_RESPONSE: payload=make([]byte,8); binary.BigEndian.PutUint32(payload,0); binary.BigEndian.PutUint16(payload[4:],p.Error); binary.BigEndian.PutUint16(payload[6:],p.ErrorIndex); for _,v:=range p.Values { payload=append(payload,valueEncode(v)...)}; case PDU_PING,PDU_CLOSE: }
 h:=make([]byte,20); h[0]=1; h[1]=byte(p.Type); h[2]=0x10; binary.BigEndian.PutUint32(h[4:],p.SessionID); binary.BigEndian.PutUint32(h[8:],p.TransactionID); binary.BigEndian.PutUint32(h[12:],p.PacketID); binary.BigEndian.PutUint32(h[16:],uint32(len(payload))); return append(h,payload...) }
func valueEncode(v VarBind) []byte { b:=[]byte{byte(v.Type>>8),byte(v.Type),0,0}; b=append(b,oidEncode(v.Name,false)...); put32:=func(n uint32){var x[4]byte;binary.BigEndian.PutUint32(x[:],n);b=append(b,x[:]...)}; switch v.Type {case TYPE_INTEGER: put32(uint32(v.Value.(int64))); case TYPE_COUNTER32,TYPE_GAUGE32,TYPE_TIMETICKS: put32(as32(v.Value)); case TYPE_COUNTER64: var x[8]byte;binary.BigEndian.PutUint64(x[:],v.Value.(uint64));b=append(b,x[:]...);case TYPE_OBJECTIDENTIFIER:b=append(b,oidEncode(v.Value.(string),false)...);case TYPE_OCTETSTRING,TYPE_IPADDRESS:b=append(b,octetEncode(v.Value.(string))...)}; return b }
func as32(v any) uint32 { switch n:=v.(type){case uint32:return n;case int64:return uint32(n);case int:return uint32(n)};return 0 }
func DecodePDU(b []byte) (*PDU,error) { if len(b)<20{return nil,fmt.Errorf("short AgentX header")}; p:=&PDU{Type:uint32(b[1]),SessionID:binary.BigEndian.Uint32(b[4:]),TransactionID:binary.BigEndian.Uint32(b[8:]),PacketID:binary.BigEndian.Uint32(b[12:])}; n:=int(binary.BigEndian.Uint32(b[16:])); if n>len(b)-20{return nil,fmt.Errorf("short AgentX payload")}; d:=b[20:20+n]; var err error; switch p.Type {case PDU_RESPONSE: if len(d)<8{return nil,fmt.Errorf("short response")}; p.Error=binary.BigEndian.Uint16(d[4:]);p.ErrorIndex=binary.BigEndian.Uint16(d[6:]);d=d[8:]; for len(d)>0 {var v VarBind;v,d,err=decodeValue(d);if err!=nil{return nil,err};p.Values=append(p.Values,v)}; case PDU_GET,PDU_GETNEXT: for len(d)>0 {var r SearchRange;r.StartOID,r.Include,d,err=decodeOID(d);if err!=nil{return nil,err};r.EndOID,_,d,err=decodeOID(d);if err!=nil{return nil,err};p.RangeList=append(p.RangeList,r)} };return p,nil }
func decodeOID(b []byte)(string,bool,[]byte,error){if len(b)<4{return "",false,nil,fmt.Errorf("short OID")};n:=int(b[0]);prefix:=b[1];inc:=b[2]!=0;b=b[4:];if len(b)<n*4{return "",false,nil,fmt.Errorf("short OID arcs")};ids:=[]uint32{};if prefix!=0{ids=[]uint32{1,3,6,1,uint32(prefix)}};for i:=0;i<n;i++{ids=append(ids,binary.BigEndian.Uint32(b[i*4:]))};parts:=make([]string,len(ids));for i,x:=range ids{parts[i]=fmt.Sprint(x)};return strings.Join(parts,"."),inc,b[n*4:],nil}
func decodeValue(b []byte)(VarBind,[]byte,error){var v VarBind;if len(b)<4{return v,nil,fmt.Errorf("short varbind")};v.Type=binary.BigEndian.Uint16(b);var e error;var rest []byte;v.Name,_,rest,e=decodeOID(b[4:]);if e!=nil{return v,nil,e};b=rest;switch v.Type{case TYPE_INTEGER,TYPE_COUNTER32,TYPE_GAUGE32,TYPE_TIMETICKS:if len(b)<4{return v,nil,fmt.Errorf("short integer")};v.Value=binary.BigEndian.Uint32(b);b=b[4:];case TYPE_COUNTER64:if len(b)<8{return v,nil,fmt.Errorf("short counter64")};v.Value=binary.BigEndian.Uint64(b);b=b[8:];case TYPE_OBJECTIDENTIFIER:v.Value,_,b,e=decodeOID(b);case TYPE_OCTETSTRING,TYPE_IPADDRESS:if len(b)<4{return v,nil,fmt.Errorf("short octet")};n:=int(binary.BigEndian.Uint32(b));pad:=(4-n%4)%4;if len(b)<4+n+pad{return v,nil,fmt.Errorf("short octet data")};v.Value=string(b[4:4+n]);b=b[4+n+pad:];case TYPE_NULL,TYPE_NOSUCHOBJECT,TYPE_NOSUCHINSTANCE,TYPE_ENDOFMIBVIEW:v.Value=nil};return v,b,e}
