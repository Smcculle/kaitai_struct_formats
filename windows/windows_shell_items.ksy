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
