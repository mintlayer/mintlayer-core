// This file is generated by rust-protobuf 3.3.0. Do not edit
// .proto file is parsed by protoc 3.12.4
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `messages-bootloader.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_3_0;

// @@protoc_insertion_point(message:hw.trezor.messages.bootloader.FirmwareErase)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct FirmwareErase {
    // message fields
    // @@protoc_insertion_point(field:hw.trezor.messages.bootloader.FirmwareErase.length)
    pub length: ::std::option::Option<u32>,
    // special fields
    // @@protoc_insertion_point(special_field:hw.trezor.messages.bootloader.FirmwareErase.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a FirmwareErase {
    fn default() -> &'a FirmwareErase {
        <FirmwareErase as ::protobuf::Message>::default_instance()
    }
}

impl FirmwareErase {
    pub fn new() -> FirmwareErase {
        ::std::default::Default::default()
    }

    // optional uint32 length = 1;

    pub fn length(&self) -> u32 {
        self.length.unwrap_or(0)
    }

    pub fn clear_length(&mut self) {
        self.length = ::std::option::Option::None;
    }

    pub fn has_length(&self) -> bool {
        self.length.is_some()
    }

    // Param is passed by value, moved
    pub fn set_length(&mut self, v: u32) {
        self.length = ::std::option::Option::Some(v);
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(1);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "length",
            |m: &FirmwareErase| { &m.length },
            |m: &mut FirmwareErase| { &mut m.length },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<FirmwareErase>(
            "FirmwareErase",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for FirmwareErase {
    const NAME: &'static str = "FirmwareErase";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                8 => {
                    self.length = ::std::option::Option::Some(is.read_uint32()?);
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.length {
            my_size += ::protobuf::rt::uint32_size(1, v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.length {
            os.write_uint32(1, v)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> FirmwareErase {
        FirmwareErase::new()
    }

    fn clear(&mut self) {
        self.length = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static FirmwareErase {
        static instance: FirmwareErase = FirmwareErase {
            length: ::std::option::Option::None,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for FirmwareErase {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("FirmwareErase").unwrap()).clone()
    }
}

impl ::std::fmt::Display for FirmwareErase {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for FirmwareErase {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:hw.trezor.messages.bootloader.FirmwareRequest)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct FirmwareRequest {
    // message fields
    // @@protoc_insertion_point(field:hw.trezor.messages.bootloader.FirmwareRequest.offset)
    pub offset: ::std::option::Option<u32>,
    // @@protoc_insertion_point(field:hw.trezor.messages.bootloader.FirmwareRequest.length)
    pub length: ::std::option::Option<u32>,
    // special fields
    // @@protoc_insertion_point(special_field:hw.trezor.messages.bootloader.FirmwareRequest.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a FirmwareRequest {
    fn default() -> &'a FirmwareRequest {
        <FirmwareRequest as ::protobuf::Message>::default_instance()
    }
}

impl FirmwareRequest {
    pub fn new() -> FirmwareRequest {
        ::std::default::Default::default()
    }

    // required uint32 offset = 1;

    pub fn offset(&self) -> u32 {
        self.offset.unwrap_or(0)
    }

    pub fn clear_offset(&mut self) {
        self.offset = ::std::option::Option::None;
    }

    pub fn has_offset(&self) -> bool {
        self.offset.is_some()
    }

    // Param is passed by value, moved
    pub fn set_offset(&mut self, v: u32) {
        self.offset = ::std::option::Option::Some(v);
    }

    // required uint32 length = 2;

    pub fn length(&self) -> u32 {
        self.length.unwrap_or(0)
    }

    pub fn clear_length(&mut self) {
        self.length = ::std::option::Option::None;
    }

    pub fn has_length(&self) -> bool {
        self.length.is_some()
    }

    // Param is passed by value, moved
    pub fn set_length(&mut self, v: u32) {
        self.length = ::std::option::Option::Some(v);
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "offset",
            |m: &FirmwareRequest| { &m.offset },
            |m: &mut FirmwareRequest| { &mut m.offset },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "length",
            |m: &FirmwareRequest| { &m.length },
            |m: &mut FirmwareRequest| { &mut m.length },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<FirmwareRequest>(
            "FirmwareRequest",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for FirmwareRequest {
    const NAME: &'static str = "FirmwareRequest";

    fn is_initialized(&self) -> bool {
        if self.offset.is_none() {
            return false;
        }
        if self.length.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                8 => {
                    self.offset = ::std::option::Option::Some(is.read_uint32()?);
                },
                16 => {
                    self.length = ::std::option::Option::Some(is.read_uint32()?);
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.offset {
            my_size += ::protobuf::rt::uint32_size(1, v);
        }
        if let Some(v) = self.length {
            my_size += ::protobuf::rt::uint32_size(2, v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.offset {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.length {
            os.write_uint32(2, v)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> FirmwareRequest {
        FirmwareRequest::new()
    }

    fn clear(&mut self) {
        self.offset = ::std::option::Option::None;
        self.length = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static FirmwareRequest {
        static instance: FirmwareRequest = FirmwareRequest {
            offset: ::std::option::Option::None,
            length: ::std::option::Option::None,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for FirmwareRequest {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("FirmwareRequest").unwrap()).clone()
    }
}

impl ::std::fmt::Display for FirmwareRequest {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for FirmwareRequest {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:hw.trezor.messages.bootloader.FirmwareUpload)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct FirmwareUpload {
    // message fields
    // @@protoc_insertion_point(field:hw.trezor.messages.bootloader.FirmwareUpload.payload)
    pub payload: ::std::option::Option<::std::vec::Vec<u8>>,
    // @@protoc_insertion_point(field:hw.trezor.messages.bootloader.FirmwareUpload.hash)
    pub hash: ::std::option::Option<::std::vec::Vec<u8>>,
    // special fields
    // @@protoc_insertion_point(special_field:hw.trezor.messages.bootloader.FirmwareUpload.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a FirmwareUpload {
    fn default() -> &'a FirmwareUpload {
        <FirmwareUpload as ::protobuf::Message>::default_instance()
    }
}

impl FirmwareUpload {
    pub fn new() -> FirmwareUpload {
        ::std::default::Default::default()
    }

    // required bytes payload = 1;

    pub fn payload(&self) -> &[u8] {
        match self.payload.as_ref() {
            Some(v) => v,
            None => &[],
        }
    }

    pub fn clear_payload(&mut self) {
        self.payload = ::std::option::Option::None;
    }

    pub fn has_payload(&self) -> bool {
        self.payload.is_some()
    }

    // Param is passed by value, moved
    pub fn set_payload(&mut self, v: ::std::vec::Vec<u8>) {
        self.payload = ::std::option::Option::Some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_payload(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.payload.is_none() {
            self.payload = ::std::option::Option::Some(::std::vec::Vec::new());
        }
        self.payload.as_mut().unwrap()
    }

    // Take field
    pub fn take_payload(&mut self) -> ::std::vec::Vec<u8> {
        self.payload.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    // optional bytes hash = 2;

    pub fn hash(&self) -> &[u8] {
        match self.hash.as_ref() {
            Some(v) => v,
            None => &[],
        }
    }

    pub fn clear_hash(&mut self) {
        self.hash = ::std::option::Option::None;
    }

    pub fn has_hash(&self) -> bool {
        self.hash.is_some()
    }

    // Param is passed by value, moved
    pub fn set_hash(&mut self, v: ::std::vec::Vec<u8>) {
        self.hash = ::std::option::Option::Some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_hash(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.hash.is_none() {
            self.hash = ::std::option::Option::Some(::std::vec::Vec::new());
        }
        self.hash.as_mut().unwrap()
    }

    // Take field
    pub fn take_hash(&mut self) -> ::std::vec::Vec<u8> {
        self.hash.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "payload",
            |m: &FirmwareUpload| { &m.payload },
            |m: &mut FirmwareUpload| { &mut m.payload },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "hash",
            |m: &FirmwareUpload| { &m.hash },
            |m: &mut FirmwareUpload| { &mut m.hash },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<FirmwareUpload>(
            "FirmwareUpload",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for FirmwareUpload {
    const NAME: &'static str = "FirmwareUpload";

    fn is_initialized(&self) -> bool {
        if self.payload.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.payload = ::std::option::Option::Some(is.read_bytes()?);
                },
                18 => {
                    self.hash = ::std::option::Option::Some(is.read_bytes()?);
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.payload.as_ref() {
            my_size += ::protobuf::rt::bytes_size(1, &v);
        }
        if let Some(v) = self.hash.as_ref() {
            my_size += ::protobuf::rt::bytes_size(2, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.payload.as_ref() {
            os.write_bytes(1, v)?;
        }
        if let Some(v) = self.hash.as_ref() {
            os.write_bytes(2, v)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> FirmwareUpload {
        FirmwareUpload::new()
    }

    fn clear(&mut self) {
        self.payload = ::std::option::Option::None;
        self.hash = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static FirmwareUpload {
        static instance: FirmwareUpload = FirmwareUpload {
            payload: ::std::option::Option::None,
            hash: ::std::option::Option::None,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for FirmwareUpload {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("FirmwareUpload").unwrap()).clone()
    }
}

impl ::std::fmt::Display for FirmwareUpload {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for FirmwareUpload {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

// @@protoc_insertion_point(message:hw.trezor.messages.bootloader.ProdTestT1)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct ProdTestT1 {
    // message fields
    // @@protoc_insertion_point(field:hw.trezor.messages.bootloader.ProdTestT1.payload)
    pub payload: ::std::option::Option<::std::vec::Vec<u8>>,
    // special fields
    // @@protoc_insertion_point(special_field:hw.trezor.messages.bootloader.ProdTestT1.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a ProdTestT1 {
    fn default() -> &'a ProdTestT1 {
        <ProdTestT1 as ::protobuf::Message>::default_instance()
    }
}

impl ProdTestT1 {
    pub fn new() -> ProdTestT1 {
        ::std::default::Default::default()
    }

    // optional bytes payload = 1;

    pub fn payload(&self) -> &[u8] {
        match self.payload.as_ref() {
            Some(v) => v,
            None => &[],
        }
    }

    pub fn clear_payload(&mut self) {
        self.payload = ::std::option::Option::None;
    }

    pub fn has_payload(&self) -> bool {
        self.payload.is_some()
    }

    // Param is passed by value, moved
    pub fn set_payload(&mut self, v: ::std::vec::Vec<u8>) {
        self.payload = ::std::option::Option::Some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_payload(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.payload.is_none() {
            self.payload = ::std::option::Option::Some(::std::vec::Vec::new());
        }
        self.payload.as_mut().unwrap()
    }

    // Take field
    pub fn take_payload(&mut self) -> ::std::vec::Vec<u8> {
        self.payload.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(1);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_option_accessor::<_, _>(
            "payload",
            |m: &ProdTestT1| { &m.payload },
            |m: &mut ProdTestT1| { &mut m.payload },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<ProdTestT1>(
            "ProdTestT1",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for ProdTestT1 {
    const NAME: &'static str = "ProdTestT1";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.payload = ::std::option::Option::Some(is.read_bytes()?);
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.payload.as_ref() {
            my_size += ::protobuf::rt::bytes_size(1, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.payload.as_ref() {
            os.write_bytes(1, v)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> ProdTestT1 {
        ProdTestT1::new()
    }

    fn clear(&mut self) {
        self.payload = ::std::option::Option::None;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static ProdTestT1 {
        static instance: ProdTestT1 = ProdTestT1 {
            payload: ::std::option::Option::None,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for ProdTestT1 {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("ProdTestT1").unwrap()).clone()
    }
}

impl ::std::fmt::Display for ProdTestT1 {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ProdTestT1 {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x19messages-bootloader.proto\x12\x1dhw.trezor.messages.bootloader\"'\
    \n\rFirmwareErase\x12\x16\n\x06length\x18\x01\x20\x01(\rR\x06length\"A\n\
    \x0fFirmwareRequest\x12\x16\n\x06offset\x18\x01\x20\x02(\rR\x06offset\
    \x12\x16\n\x06length\x18\x02\x20\x02(\rR\x06length\">\n\x0eFirmwareUploa\
    d\x12\x18\n\x07payload\x18\x01\x20\x02(\x0cR\x07payload\x12\x12\n\x04has\
    h\x18\x02\x20\x01(\x0cR\x04hash\"&\n\nProdTestT1\x12\x18\n\x07payload\
    \x18\x01\x20\x01(\x0cR\x07payloadB>\n#com.satoshilabs.trezor.lib.protobu\
    fB\x17TrezorMessageBootloader\
";

/// `FileDescriptorProto` object which was a source for this generated file
fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    static file_descriptor_proto_lazy: ::protobuf::rt::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::Lazy::new();
    file_descriptor_proto_lazy.get(|| {
        ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
    })
}

/// `FileDescriptor` object which allows dynamic access to files
pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
    static generated_file_descriptor_lazy: ::protobuf::rt::Lazy<::protobuf::reflect::GeneratedFileDescriptor> = ::protobuf::rt::Lazy::new();
    static file_descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::FileDescriptor> = ::protobuf::rt::Lazy::new();
    file_descriptor.get(|| {
        let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
            let mut deps = ::std::vec::Vec::with_capacity(0);
            let mut messages = ::std::vec::Vec::with_capacity(4);
            messages.push(FirmwareErase::generated_message_descriptor_data());
            messages.push(FirmwareRequest::generated_message_descriptor_data());
            messages.push(FirmwareUpload::generated_message_descriptor_data());
            messages.push(ProdTestT1::generated_message_descriptor_data());
            let mut enums = ::std::vec::Vec::with_capacity(0);
            ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
                file_descriptor_proto(),
                deps,
                messages,
                enums,
            )
        });
        ::protobuf::reflect::FileDescriptor::new_generated_2(generated_file_descriptor)
    })
}
