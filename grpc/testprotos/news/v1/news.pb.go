// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Note (@Sourcegraph): This file was copied / adapted from
// https://github.com/protocolbuffers/protobuf-go/blob/v1.30.0/internal/testprotos/news/news.proto to aid our testing.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.29.1
// 	protoc        (unknown)
// source: news.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Article_Status int32

const (
	Article_STATUS_DRAFT_UNSPECIFIED Article_Status = 0
	Article_STATUS_PUBLISHED         Article_Status = 1
	Article_STATUS_REVOKED           Article_Status = 2
)

// Enum value maps for Article_Status.
var (
	Article_Status_name = map[int32]string{
		0: "STATUS_DRAFT_UNSPECIFIED",
		1: "STATUS_PUBLISHED",
		2: "STATUS_REVOKED",
	}
	Article_Status_value = map[string]int32{
		"STATUS_DRAFT_UNSPECIFIED": 0,
		"STATUS_PUBLISHED":         1,
		"STATUS_REVOKED":           2,
	}
)

func (x Article_Status) Enum() *Article_Status {
	p := new(Article_Status)
	*p = x
	return p
}

func (x Article_Status) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Article_Status) Descriptor() protoreflect.EnumDescriptor {
	return file_news_proto_enumTypes[0].Descriptor()
}

func (Article_Status) Type() protoreflect.EnumType {
	return &file_news_proto_enumTypes[0]
}

func (x Article_Status) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Article_Status.Descriptor instead.
func (Article_Status) EnumDescriptor() ([]byte, []int) {
	return file_news_proto_rawDescGZIP(), []int{0, 0}
}

type Article struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Author      string                 `protobuf:"bytes,1,opt,name=author,proto3" json:"author,omitempty"`
	Date        *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=date,proto3" json:"date,omitempty"`
	Title       string                 `protobuf:"bytes,3,opt,name=title,proto3" json:"title,omitempty"`
	Content     string                 `protobuf:"bytes,4,opt,name=content,proto3" json:"content,omitempty"`
	Status      Article_Status         `protobuf:"varint,8,opt,name=status,proto3,enum=grpc.testprotos.news.v1.Article_Status" json:"status,omitempty"`
	Attachments []*Attachment          `protobuf:"bytes,7,rep,name=attachments,proto3" json:"attachments,omitempty"`
}

func (x *Article) Reset() {
	*x = Article{}
	if protoimpl.UnsafeEnabled {
		mi := &file_news_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Article) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Article) ProtoMessage() {}

func (x *Article) ProtoReflect() protoreflect.Message {
	mi := &file_news_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Article.ProtoReflect.Descriptor instead.
func (*Article) Descriptor() ([]byte, []int) {
	return file_news_proto_rawDescGZIP(), []int{0}
}

func (x *Article) GetAuthor() string {
	if x != nil {
		return x.Author
	}
	return ""
}

func (x *Article) GetDate() *timestamppb.Timestamp {
	if x != nil {
		return x.Date
	}
	return nil
}

func (x *Article) GetTitle() string {
	if x != nil {
		return x.Title
	}
	return ""
}

func (x *Article) GetContent() string {
	if x != nil {
		return x.Content
	}
	return ""
}

func (x *Article) GetStatus() Article_Status {
	if x != nil {
		return x.Status
	}
	return Article_STATUS_DRAFT_UNSPECIFIED
}

func (x *Article) GetAttachments() []*Attachment {
	if x != nil {
		return x.Attachments
	}
	return nil
}

type Attachment struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Contents:
	//
	//	*Attachment_BinaryAttachment
	//	*Attachment_KeyValueAttachment
	Contents isAttachment_Contents `protobuf_oneof:"contents"`
}

func (x *Attachment) Reset() {
	*x = Attachment{}
	if protoimpl.UnsafeEnabled {
		mi := &file_news_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Attachment) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Attachment) ProtoMessage() {}

func (x *Attachment) ProtoReflect() protoreflect.Message {
	mi := &file_news_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Attachment.ProtoReflect.Descriptor instead.
func (*Attachment) Descriptor() ([]byte, []int) {
	return file_news_proto_rawDescGZIP(), []int{1}
}

func (m *Attachment) GetContents() isAttachment_Contents {
	if m != nil {
		return m.Contents
	}
	return nil
}

func (x *Attachment) GetBinaryAttachment() *BinaryAttachment {
	if x, ok := x.GetContents().(*Attachment_BinaryAttachment); ok {
		return x.BinaryAttachment
	}
	return nil
}

func (x *Attachment) GetKeyValueAttachment() *KeyValueAttachment {
	if x, ok := x.GetContents().(*Attachment_KeyValueAttachment); ok {
		return x.KeyValueAttachment
	}
	return nil
}

type isAttachment_Contents interface {
	isAttachment_Contents()
}

type Attachment_BinaryAttachment struct {
	BinaryAttachment *BinaryAttachment `protobuf:"bytes,1,opt,name=binary_attachment,json=binaryAttachment,proto3,oneof"`
}

type Attachment_KeyValueAttachment struct {
	KeyValueAttachment *KeyValueAttachment `protobuf:"bytes,2,opt,name=key_value_attachment,json=keyValueAttachment,proto3,oneof"`
}

func (*Attachment_BinaryAttachment) isAttachment_Contents() {}

func (*Attachment_KeyValueAttachment) isAttachment_Contents() {}

type BinaryAttachment struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Data []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *BinaryAttachment) Reset() {
	*x = BinaryAttachment{}
	if protoimpl.UnsafeEnabled {
		mi := &file_news_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BinaryAttachment) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BinaryAttachment) ProtoMessage() {}

func (x *BinaryAttachment) ProtoReflect() protoreflect.Message {
	mi := &file_news_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BinaryAttachment.ProtoReflect.Descriptor instead.
func (*BinaryAttachment) Descriptor() ([]byte, []int) {
	return file_news_proto_rawDescGZIP(), []int{2}
}

func (x *BinaryAttachment) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *BinaryAttachment) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

type KeyValueAttachment struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string            `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Data map[string]string `protobuf:"bytes,2,rep,name=data,proto3" json:"data,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *KeyValueAttachment) Reset() {
	*x = KeyValueAttachment{}
	if protoimpl.UnsafeEnabled {
		mi := &file_news_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyValueAttachment) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyValueAttachment) ProtoMessage() {}

func (x *KeyValueAttachment) ProtoReflect() protoreflect.Message {
	mi := &file_news_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyValueAttachment.ProtoReflect.Descriptor instead.
func (*KeyValueAttachment) Descriptor() ([]byte, []int) {
	return file_news_proto_rawDescGZIP(), []int{3}
}

func (x *KeyValueAttachment) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *KeyValueAttachment) GetData() map[string]string {
	if x != nil {
		return x.Data
	}
	return nil
}

var File_news_proto protoreflect.FileDescriptor

var file_news_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x6e, 0x65, 0x77, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x17, 0x67, 0x72,
	0x70, 0x63, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x6e, 0x65,
	0x77, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xdb, 0x02, 0x0a, 0x07, 0x41, 0x72, 0x74, 0x69, 0x63,
	0x6c, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x12, 0x2e, 0x0a, 0x04, 0x64, 0x61,
	0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x52, 0x04, 0x64, 0x61, 0x74, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x69,
	0x74, 0x6c, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x69, 0x74, 0x6c, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12, 0x3f, 0x0a, 0x06, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x27, 0x2e, 0x67, 0x72, 0x70,
	0x63, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x6e, 0x65, 0x77,
	0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x72, 0x74, 0x69, 0x63, 0x6c, 0x65, 0x2e, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x45, 0x0a, 0x0b, 0x61,
	0x74, 0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x23, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x73, 0x2e, 0x6e, 0x65, 0x77, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x74, 0x74, 0x61, 0x63,
	0x68, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x0b, 0x61, 0x74, 0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e,
	0x74, 0x73, 0x22, 0x50, 0x0a, 0x06, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x1c, 0x0a, 0x18,
	0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x44, 0x52, 0x41, 0x46, 0x54, 0x5f, 0x55, 0x4e, 0x53,
	0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x14, 0x0a, 0x10, 0x53, 0x54,
	0x41, 0x54, 0x55, 0x53, 0x5f, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x53, 0x48, 0x45, 0x44, 0x10, 0x01,
	0x12, 0x12, 0x0a, 0x0e, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x52, 0x45, 0x56, 0x4f, 0x4b,
	0x45, 0x44, 0x10, 0x02, 0x22, 0xd3, 0x01, 0x0a, 0x0a, 0x41, 0x74, 0x74, 0x61, 0x63, 0x68, 0x6d,
	0x65, 0x6e, 0x74, 0x12, 0x58, 0x0a, 0x11, 0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x5f, 0x61, 0x74,
	0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29,
	0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73,
	0x2e, 0x6e, 0x65, 0x77, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x42, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x41,
	0x74, 0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e, 0x74, 0x48, 0x00, 0x52, 0x10, 0x62, 0x69, 0x6e,
	0x61, 0x72, 0x79, 0x41, 0x74, 0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x5f, 0x0a,
	0x14, 0x6b, 0x65, 0x79, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x5f, 0x61, 0x74, 0x74, 0x61, 0x63,
	0x68, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2b, 0x2e, 0x67, 0x72,
	0x70, 0x63, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x6e, 0x65,
	0x77, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4b, 0x65, 0x79, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x41, 0x74,
	0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e, 0x74, 0x48, 0x00, 0x52, 0x12, 0x6b, 0x65, 0x79, 0x56,
	0x61, 0x6c, 0x75, 0x65, 0x41, 0x74, 0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e, 0x74, 0x42, 0x0a,
	0x0a, 0x08, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x22, 0x3a, 0x0a, 0x10, 0x42, 0x69,
	0x6e, 0x61, 0x72, 0x79, 0x41, 0x74, 0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0xac, 0x01, 0x0a, 0x12, 0x4b, 0x65, 0x79, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x41, 0x74, 0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x12, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x49, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x35, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x73, 0x2e, 0x6e, 0x65, 0x77, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4b, 0x65, 0x79, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x41, 0x74, 0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e, 0x74, 0x2e, 0x44, 0x61, 0x74,
	0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x1a, 0x37, 0x0a, 0x09,
	0x44, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x33, 0x5a, 0x31, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x78, 0x76, 0x61, 0x6e, 0x64, 0x69, 0x73, 0x68, 0x2f, 0x7a, 0x6f, 0x65,
	0x6b, 0x74, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x73, 0x2f, 0x6e, 0x65, 0x77, 0x73, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_news_proto_rawDescOnce sync.Once
	file_news_proto_rawDescData = file_news_proto_rawDesc
)

func file_news_proto_rawDescGZIP() []byte {
	file_news_proto_rawDescOnce.Do(func() {
		file_news_proto_rawDescData = protoimpl.X.CompressGZIP(file_news_proto_rawDescData)
	})
	return file_news_proto_rawDescData
}

var file_news_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_news_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_news_proto_goTypes = []interface{}{
	(Article_Status)(0),           // 0: grpc.testprotos.news.v1.Article.Status
	(*Article)(nil),               // 1: grpc.testprotos.news.v1.Article
	(*Attachment)(nil),            // 2: grpc.testprotos.news.v1.Attachment
	(*BinaryAttachment)(nil),      // 3: grpc.testprotos.news.v1.BinaryAttachment
	(*KeyValueAttachment)(nil),    // 4: grpc.testprotos.news.v1.KeyValueAttachment
	nil,                           // 5: grpc.testprotos.news.v1.KeyValueAttachment.DataEntry
	(*timestamppb.Timestamp)(nil), // 6: google.protobuf.Timestamp
}
var file_news_proto_depIdxs = []int32{
	6, // 0: grpc.testprotos.news.v1.Article.date:type_name -> google.protobuf.Timestamp
	0, // 1: grpc.testprotos.news.v1.Article.status:type_name -> grpc.testprotos.news.v1.Article.Status
	2, // 2: grpc.testprotos.news.v1.Article.attachments:type_name -> grpc.testprotos.news.v1.Attachment
	3, // 3: grpc.testprotos.news.v1.Attachment.binary_attachment:type_name -> grpc.testprotos.news.v1.BinaryAttachment
	4, // 4: grpc.testprotos.news.v1.Attachment.key_value_attachment:type_name -> grpc.testprotos.news.v1.KeyValueAttachment
	5, // 5: grpc.testprotos.news.v1.KeyValueAttachment.data:type_name -> grpc.testprotos.news.v1.KeyValueAttachment.DataEntry
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_news_proto_init() }
func file_news_proto_init() {
	if File_news_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_news_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Article); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_news_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Attachment); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_news_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BinaryAttachment); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_news_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyValueAttachment); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_news_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*Attachment_BinaryAttachment)(nil),
		(*Attachment_KeyValueAttachment)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_news_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_news_proto_goTypes,
		DependencyIndexes: file_news_proto_depIdxs,
		EnumInfos:         file_news_proto_enumTypes,
		MessageInfos:      file_news_proto_msgTypes,
	}.Build()
	File_news_proto = out.File
	file_news_proto_rawDesc = nil
	file_news_proto_goTypes = nil
	file_news_proto_depIdxs = nil
}
