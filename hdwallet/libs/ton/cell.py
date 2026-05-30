#!/usr/bin/env python3

# Copyright © 2020-2026, Abenezer Lulseged Wube <itsm3abena@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import math
from hashlib import sha256
from typing import List, Tuple


class BitString:

    def __init__(self, length: int):
        self.array = bytearray(math.ceil(length / 8))
        self.cursor = 0
        self.length = length

    def get(self, index: int) -> int:
        return int((self.array[index // 8] & (1 << (7 - (index % 8)))) > 0)

    def write_bit(self, value: int) -> None:
        if value:
            self.array[self.cursor // 8] |= 1 << (7 - (self.cursor % 8))
        else:
            self.array[self.cursor // 8] &= ~(1 << (7 - (self.cursor % 8)))
        self.cursor += 1

    def write_bit_array(self, bits: str) -> None:
        for bit in bits:
            self.write_bit(int(bit))

    def write_uint(self, number: int, bit_length: int) -> None:
        if bit_length == 0:
            return
        if number != 0 and len(bin(number)[2:]) > bit_length:
            raise ValueError(f"bitLength is too small for number, got number={number}, bitLength={bit_length}")
        for index in range(bit_length, 0, -1):
            mask = 2 ** (index - 1)
            self.write_bit(1 if number >= mask else 0)
            if number >= mask:
                number -= mask

    def write_bytes(self, data: bytes) -> None:
        for byte in data:
            self.write_uint(byte, 8)

    def get_top_upped_array(self) -> bytes:
        padding = math.ceil(self.cursor / 8) * 8 - self.cursor
        if padding:
            padding -= 1
            self.write_bit(1)
            while padding:
                padding -= 1
                self.write_bit(0)
        return bytes(self.array[:math.ceil(self.cursor / 8)])


class Cell:

    REACH_BOC_MAGIC_PREFIX = bytes.fromhex("B5EE9C72")

    def __init__(self) -> None:
        self.bits = BitString(1023)
        self.refs: List["Cell"] = []

    def write_cell(self, other: "Cell") -> None:
        for bit_index in range(other.bits.cursor):
            self.bits.write_bit(other.bits.get(bit_index))
        self.refs.extend(other.refs)

    def bytes_hash(self) -> bytes:
        return sha256(self.bytes_repr()).digest()

    def bytes_repr(self) -> bytes:
        payload = self.get_data_with_descriptors()
        for reference in self.refs:
            payload += reference.get_max_depth_as_array()
        for reference in self.refs:
            payload += reference.bytes_hash()
        return payload

    def get_data_with_descriptors(self) -> bytes:
        return self.get_refs_descriptor() + self.get_bits_descriptor() + self.bits.get_top_upped_array()

    def get_bits_descriptor(self) -> bytes:
        return bytes([math.ceil(self.bits.cursor / 8) + math.floor(self.bits.cursor / 8)])

    def get_refs_descriptor(self) -> bytes:
        return bytes([len(self.refs)])

    def get_max_depth(self) -> int:
        if not self.refs:
            return 0
        return max(reference.get_max_depth() for reference in self.refs) + 1

    def get_max_depth_as_array(self) -> bytes:
        max_depth = self.get_max_depth()
        return bytes([max_depth // 256, max_depth % 256])

    def tree_walk(self) -> Tuple[List[Tuple[bytes, "Cell"]], dict]:
        return _tree_walk(self, [], {})

    def serialize_for_boc(self, cells_index: dict, ref_size: int) -> bytes:
        payload = self.get_data_with_descriptors()
        for reference in self.refs:
            ref_index = cells_index[reference.bytes_hash()]
            ref_hex = format(ref_index, "x")
            if len(ref_hex) % 2:
                ref_hex = "0" + ref_hex
            payload += bytes.fromhex(ref_hex)
        return payload

    def boc_serialization_size(self, cells_index: dict, ref_size: int) -> int:
        return len(self.serialize_for_boc(cells_index, ref_size))

    @staticmethod
    def one_from_boc(serialized_boc: bytes) -> "Cell":
        cells = deserialize_boc(serialized_boc)
        if len(cells) != 1:
            raise ValueError("Expected 1 root cell")
        return cells[0]


def _tree_walk(cell: Cell, topological_order: list, index_hashmap: dict, parent_hash: bytes = None):
    cell_hash = cell.bytes_hash()
    if cell_hash in index_hashmap:
        if parent_hash and index_hashmap[parent_hash] > index_hashmap[cell_hash]:
            topological_order, index_hashmap = _move_to_end(index_hashmap, topological_order, cell_hash)
        return topological_order, index_hashmap

    index_hashmap[cell_hash] = len(topological_order)
    topological_order.append((cell_hash, cell))
    for sub_cell in cell.refs:
        topological_order, index_hashmap = _tree_walk(sub_cell, topological_order, index_hashmap, cell_hash)
    return topological_order, index_hashmap


def _move_to_end(index_hashmap: dict, topological_order: list, target: bytes):
    target_index = index_hashmap[target]
    for cell_hash in list(index_hashmap):
        if index_hashmap[cell_hash] > target_index:
            index_hashmap[cell_hash] -= 1
    index_hashmap[target] = len(topological_order) - 1
    data = topological_order.pop(target_index)
    topological_order.append(data)
    for sub_cell in data[1].refs:
        topological_order, index_hashmap = _move_to_end(index_hashmap, topological_order, sub_cell.bytes_hash())
    return topological_order, index_hashmap


def _read_n_bytes_uint_from_array(size_bytes: int, data: bytes) -> int:
    value = 0
    for byte in data[:size_bytes]:
        value = (value << 8) + byte
    return value


def _crc32c(data: bytes) -> bytes:
    poly = 0x82F63B78
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc >> 1) ^ poly) if (crc & 1) else (crc >> 1)
    crc ^= 0xFFFFFFFF
    return crc.to_bytes(4, "little")


def deserialize_boc(serialized_boc: bytes) -> List[Cell]:
    input_data = serialized_boc
    if len(serialized_boc) < 5:
        raise ValueError("Not enough bytes for BoC header")

    if serialized_boc[:4] != Cell.REACH_BOC_MAGIC_PREFIX:
        raise ValueError("Unsupported BoC magic prefix")

    flags_byte = serialized_boc[4]
    has_idx = flags_byte & 128
    hash_crc32 = flags_byte & 64
    size_bytes = flags_byte % 8
    serialized_boc = serialized_boc[5:]

    if len(serialized_boc) < 1 + 5 * size_bytes:
        raise ValueError("Not enough bytes for encoding cells counters")

    offset_bytes = serialized_boc[0]
    serialized_boc = serialized_boc[1:]
    cells_num = _read_n_bytes_uint_from_array(size_bytes, serialized_boc)
    serialized_boc = serialized_boc[size_bytes:]
    roots_num = _read_n_bytes_uint_from_array(size_bytes, serialized_boc)
    serialized_boc = serialized_boc[size_bytes:]
    _read_n_bytes_uint_from_array(size_bytes, serialized_boc)
    serialized_boc = serialized_boc[size_bytes:]
    tot_cells_size = _read_n_bytes_uint_from_array(offset_bytes, serialized_boc)
    serialized_boc = serialized_boc[offset_bytes:]

    root_list = []
    for _ in range(roots_num):
        root_list.append(_read_n_bytes_uint_from_array(size_bytes, serialized_boc))
        serialized_boc = serialized_boc[size_bytes:]

    if has_idx:
        for _ in range(cells_num):
            _read_n_bytes_uint_from_array(offset_bytes, serialized_boc)
            serialized_boc = serialized_boc[offset_bytes:]

    cells_data = serialized_boc[:tot_cells_size]
    serialized_boc = serialized_boc[tot_cells_size:]

    if hash_crc32:
        if len(serialized_boc) < 4:
            raise ValueError("Not enough bytes for crc32c hashsum")
        if _crc32c(input_data[:-4]) != serialized_boc[:4]:
            raise ValueError("Crc32c hashsum mismatch")

    cells_array = []
    for _ in range(cells_num):
        cell, cells_data = _deserialize_cell_data(cells_data, size_bytes)
        cells_array.append(cell)

    for cell_index in reversed(range(cells_num)):
        cell = cells_array[cell_index]
        for ref_index in range(len(cell.refs)):
            reference = cell.refs[ref_index]
            if reference < cell_index:
                raise ValueError("Topological order is broken")
            cell.refs[ref_index] = cells_array[reference]

    return [cells_array[root_index] for root_index in root_list]


def _deserialize_cell_data(cell_data: bytes, reference_index_size: int):
    if len(cell_data) < 2:
        raise ValueError("Not enough bytes to encode cell descriptors")

    d1, d2 = cell_data[0], cell_data[1]
    cell_data = cell_data[2:]
    ref_num = d1 % 8
    data_bytes_size = math.ceil(d2 / 2)
    fullfilled_bytes = not (d2 % 2)

    cell = Cell()
    if len(cell_data) < data_bytes_size + reference_index_size * ref_num:
        raise ValueError("Not enough bytes to encode cell data")

    cell.bits.cursor = len(cell_data[:data_bytes_size]) * 8
    cell.bits.array = bytearray(cell_data[:data_bytes_size])
    if not fullfilled_bytes and cell.bits.cursor:
        found_end_bit = False
        for _ in range(7):
            cell.bits.cursor -= 1
            if cell.bits.get(cell.bits.cursor):
                found_end_bit = True
                cell.bits.array[cell.bits.cursor // 8] &= ~(1 << (7 - (cell.bits.cursor % 8)))
                break
        if not found_end_bit:
            raise ValueError("Incorrect top-upped array")

    cell_data = cell_data[data_bytes_size:]
    for _ in range(ref_num):
        cell.refs.append(_read_n_bytes_uint_from_array(reference_index_size, cell_data))
        cell_data = cell_data[reference_index_size:]

    return cell, cell_data
