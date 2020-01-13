meta:
  id: windows_shell_items
  title: Windows Shell Items
  xref:
    forensicswiki: Shell Item
  license: CC0-1.0
  imports:
    - dos_datetime
  encoding: windows-1257
  endian: le
doc: |
  Windows Shell Items (AKA "shellbags") is an undocumented set of
  structures used internally within Windows to identify paths in
  Windows Folder Hierarchy. It is widely used in Windows Shell (and
  most visible in File Explorer), both as in-memory and in-file
  structures. Some formats embed them, namely:

  * Windows Shell link files (.lnk) Windows registry
  * Windows registry "ShellBags" keys

  The format is mostly undocumented, and is known to vary between
  various Windows versions.
doc-ref: https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc
seq:
  - id: items
    -orig-id: IDList
    type: shell_item
    repeat: until
    repeat-until: _.len_data == 0
    doc-ref: 'https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf Section 2.2.1'
types:
  shell_item:
    -orig-id: ItemID
    doc-ref: 'https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf Section 2.2.2'
    seq:
      - id: len_data
        type: u2
      - id: data
        size: len_data - 2
        type: shell_item_data
        if: len_data >= 2
  shell_item_data:
    seq:
      - id: class_type
        type: u1
        doc: |
          Class type is a combination of a type, subtype, and flags. It has not
          proven to be foolproof for all shell items, but appears to be a
          strong one for known formats. Shell items fall into 2 broad categories
          of type-based items or signature-base items, with most signature
          items having a class_type of 0x00.
      - id: body
        type:
          switch-on: switch_value
          cases:
            0x1f: root_folder_body
            0x20: volume_body
            0x30: file_entry_body
    instances:
      mask_type:
        value: class_type & 0x70
      switch_value:
        value: 'mask_type == 0x20 or mask_type == 0x30 or mask_type == 0x40 ? mask_type : class_type'
  root_folder_body:
    doc-ref: 'https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#32-root-folder-shell-item'
    seq:
      - id: sort_index
        type: u1
      - id: shell_folder_id
        size: 16
      # TODO: Extension block 0xbeef0017 if size > 20
  volume_body:
    doc-ref: 'https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#33-volume-shell-item'
    seq:
      - id: flags
        type: u1
  file_entry_body:
    doc-ref: 'https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#34-file-entry-shell-item'
    seq:
      - size: 1
      - id: file_size
        type: u4
      - id: modified
        type: dos_datetime
      - id: file_attrs
        type: u2
      - id: short_unicode_name
        type: terminated_utf16le(0)
        if: has_unicode_name
      - id: short_ansi_name
        terminator: 0
        if: not has_unicode_name
      - id: zero_padding
        size: (2 - _io.pos) % 2
      - id: ext_blocks
        type: extension_block
        repeat: until
        repeat-until: _io.pos >= _io.size - 2
        if: ext_offset > 0
    instances:
      is_dir:
        value: _parent.class_type & 0x01 != 0
      is_file:
        value: _parent.class_type & 0x02 != 0
      has_unicode_name:
        value: _parent.class_type & 0x04 != 0
      ext_offset:
        pos: _io.size - 2
        type: u2

  terminated_utf16le:
    doc: Modified hack from windows_resource_file.ksy to read utf-16le string.
    doc-ref: https://github.com/kaitai-io/kaitai_struct_formats/blob/master/windows/windows_resource_file.ksy
    params:
      - id: terminator_value
        type: u2
    seq:
      - id: save_start_noop
        size: 0
        if: save_start >= 0  # Save starting offset
      - id: rest
        type: u2
        repeat: until
        repeat-until: _ == terminator_value
      - id: save_end_noop
        size: 0
        if: save_end >= 0  # Save ending offset
    instances:
      # Super dirty hack saves start/end positions to re-read it as string
      save_start:
        value: _io.pos
      save_end:
        value: _io.pos
      len_str:
        value: 'save_end - save_start - 2'
      as_string:
        pos: save_start
        size: len_str
        type: str
        encoding: utf-16le
        if: len_str > 0

  extension_block:
    doc: Implementation of extension block types.
    doc-ref: https://github.com/libyal/libfwsi/blob/master/documentation/Windows%20Shell%20Item%20format.asciidoc#extension_block_0xbeef0000
    seq:
      - id: len_data
        type: u2
      - id: version
        type: u2
      - id: signature
        type: u4
        enum: signature
      - id: data
        size: len_data - 8
        type:
          switch-on: signature
          cases:
            'signature::beef0003': beef0003
            'signature::beef0004': beef0004
            'signature::beef0005': beef0005
            'signature::beef0006': beef0006
            'signature::beef0008': beef0008
            'signature::beef001a': beef001a
            'signature::beef001b': beef001a
    enums:
      signature:
        0xBEEF0003: beef0003
        0xBEEF0004: beef0004
        0xBEEF0005: beef0005
        0xBEEF0006: beef0006
        0xBEEF0008: beef0008
        0xBEEF001A: beef001a
        0xBEEF001B: beef001b

    types:
      file_ref:
        doc: NTFS file reference
        seq:
          - id: entry_index
            size: 6
          - id: sequence_number
            type: u2


      beef0000:
        doc: |
          This block has been reported to have a data size of 6 or 34. When the
          size is 34, it contains two UUIDs (16 + 16) and the standard 2-byte
          extension block footer. Structure is similar to beef0019.
        instances:
          uuid1:
            pos: 0
            size: 16
            if: _io.size == 34
          uuid2:
            pos: 0x10
            size: 16
            if: _io.size == 34

      beef0003:
        seq:
          - id: uuid
            size: 16

      beef0004:
        doc: |
          The most common type of extension block found in file entry and
          delegate items.
        seq:
          - id: created
            type: dos_datetime
          - id: accessed
            type: dos_datetime
          - id: identifier
            type: u2
          - size: 2
            doc: Empty
            if: version >= 0x0007
          - id: mft_ref
            type: file_ref
            if: version >= 0x0007
          - size: 8
            doc: Unknown
            if: version >= 0x0007
          - id: localized_name_size
            type: u2
            if: version >= 0x0003
          - size: 4
            doc: Empty
            if: version >= 0x0009
          - size: 4
            doc: Unknown
            if: version >= 0x0008
          - id: long_name_block
            type: terminated_utf16le(0)
          - id: localized_name_block
            type: terminated_utf16le(0)
            if: has_localized_name
          - id: ext_block_offset
            type: u2
        instances:
          version:
            value: _parent.version
          has_localized_name:
            value: version >= 0x0003 and localized_name_size > 0
          ext_block_name:
            value: long_name_block.as_string
          localized_name:
            value: localized_name_block.as_string

      beef0005:
        seq:
          - id: uuid
            size: 16
            doc: |
              This is noted as empty in the shell specification, but has been
              found to contain a UUID in the wild.
          - id: shitem_list
            size-eos: true
            type: windows_shell_items

      beef0006:
        seq:
          - id: username
            type: terminated_utf16le(0)
        instances:
          ext_block_name:
            value: username.as_string

      beef0008:
        doc: |
          This block is created when an item in the recycle bin is interacted
          with in Explorer or a com dialog box. Contains deletion, $R path, and
          original path information.
        seq:
          - size: 8
            doc: Unknown
          - id: deleted
            type: u8
            doc: Deletion time as number of 100-nanosecond intervals since 1601
          - size: 4
            doc: Unknown, possible version string
          - id: original_path_full
            type: terminated_utf16le(0)
            doc: Terminated by an unknown 2 bytes that are non-empty
          - id: recycle_path
            type: str
            encoding: utf-16
            size: _parent.len_data - _io.pos - 10
            doc: |
              Path to $R file takes up the remaining length of the
              extension block, leaving 2 bytes for the ending sequence. Since
              the data section has an 8-byte header, we subtract 10 from the
              size.
        instances:
          original_path:
            # Trim unknown character at the end
            value: original_path_full.as_string.substring(0, original_path_full.as_string.length - 1)

      beef001a:
        doc: |
          This extension block has been seen in lnk files. Seen to
          share the same format as beef001b.
        seq:
          - size: 2
          - id: name_block
            type: terminated_utf16le(0)
          - id: shitem_list
            repeat: until
            repeat-until: _io.pos > _io.size - 2
            type: windows_shell_items
            if: _io.pos < _io.size - 2
            doc: |
              Repeat until the last 2 bytes, which should be the first
              extension block offset. May not be present.
          - size: 2
        instances:
          ext_block_name:
            value: name_block.as_string
