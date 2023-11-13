// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk
// This is a custom proprietary block cypher based on AES.
// Reverse engineered from the wild.

use byte_slice_cast::{AsSliceOf, AsByteSlice};

const RCON: [u32; 12] = [
    0x517CC1B7, 0x27220A94, 0xFE13ABE8, 0xFA9A6EE0, 0x6DB14ACC, 0x9E21C820, 0xFF28B1D5, 0xEF5DE2B0,
    0xDB92371D, 0x2126E970, 0x03249775, 0x04E8C90E,
];

const SBOX0: [u32; 256] = [
    0x30303000, 0x68686800, 0x99999900, 0x1B1B1B00, 0x87878700, 0xB9B9B900, 0x21212100, 0x78787800,
    0x50505000, 0x39393900, 0xDBDBDB00, 0xE1E1E100, 0x72727200, 0x09090900, 0x62626200, 0x3C3C3C00,
    0x3E3E3E00, 0x7E7E7E00, 0x5E5E5E00, 0x8E8E8E00, 0xF1F1F100, 0xA0A0A000, 0xCCCCCC00, 0xA3A3A300,
    0x2A2A2A00, 0x1D1D1D00, 0xFBFBFB00, 0xB6B6B600, 0xD6D6D600, 0x20202000, 0xC4C4C400, 0x8D8D8D00,
    0x81818100, 0x65656500, 0xF5F5F500, 0x89898900, 0xCBCBCB00, 0x9D9D9D00, 0x77777700, 0xC6C6C600,
    0x57575700, 0x43434300, 0x56565600, 0x17171700, 0xD4D4D400, 0x40404000, 0x1A1A1A00, 0x4D4D4D00,
    0xC0C0C000, 0x63636300, 0x6C6C6C00, 0xE3E3E300, 0xB7B7B700, 0xC8C8C800, 0x64646400, 0x6A6A6A00,
    0x53535300, 0xAAAAAA00, 0x38383800, 0x98989800, 0x0C0C0C00, 0xF4F4F400, 0x9B9B9B00, 0xEDEDED00,
    0x7F7F7F00, 0x22222200, 0x76767600, 0xAFAFAF00, 0xDDDDDD00, 0x3A3A3A00, 0x0B0B0B00, 0x58585800,
    0x67676700, 0x88888800, 0x06060600, 0xC3C3C300, 0x35353500, 0x0D0D0D00, 0x01010100, 0x8B8B8B00,
    0x8C8C8C00, 0xC2C2C200, 0xE6E6E600, 0x5F5F5F00, 0x02020200, 0x24242400, 0x75757500, 0x93939300,
    0x66666600, 0x1E1E1E00, 0xE5E5E500, 0xE2E2E200, 0x54545400, 0xD8D8D800, 0x10101000, 0xCECECE00,
    0x7A7A7A00, 0xE8E8E800, 0x08080800, 0x2C2C2C00, 0x12121200, 0x97979700, 0x32323200, 0xABABAB00,
    0xB4B4B400, 0x27272700, 0x0A0A0A00, 0x23232300, 0xDFDFDF00, 0xEFEFEF00, 0xCACACA00, 0xD9D9D900,
    0xB8B8B800, 0xFAFAFA00, 0xDCDCDC00, 0x31313100, 0x6B6B6B00, 0xD1D1D100, 0xADADAD00, 0x19191900,
    0x49494900, 0xBDBDBD00, 0x51515100, 0x96969600, 0xEEEEEE00, 0xE4E4E400, 0xA8A8A800, 0x41414100,
    0xDADADA00, 0xFFFFFF00, 0xCDCDCD00, 0x55555500, 0x86868600, 0x36363600, 0xBEBEBE00, 0x61616100,
    0x52525200, 0xF8F8F800, 0xBBBBBB00, 0x0E0E0E00, 0x82828200, 0x48484800, 0x69696900, 0x9A9A9A00,
    0xE0E0E000, 0x47474700, 0x9E9E9E00, 0x5C5C5C00, 0x04040400, 0x4B4B4B00, 0x34343400, 0x15151500,
    0x79797900, 0x26262600, 0xA7A7A700, 0xDEDEDE00, 0x29292900, 0xAEAEAE00, 0x92929200, 0xD7D7D700,
    0x84848400, 0xE9E9E900, 0xD2D2D200, 0xBABABA00, 0x5D5D5D00, 0xF3F3F300, 0xC5C5C500, 0xB0B0B000,
    0xBFBFBF00, 0xA4A4A400, 0x3B3B3B00, 0x71717100, 0x44444400, 0x46464600, 0x2B2B2B00, 0xFCFCFC00,
    0xEBEBEB00, 0x6F6F6F00, 0xD5D5D500, 0xF6F6F600, 0x14141400, 0xFEFEFE00, 0x7C7C7C00, 0x70707000,
    0x5A5A5A00, 0x7D7D7D00, 0xFDFDFD00, 0x2F2F2F00, 0x18181800, 0x83838300, 0x16161600, 0xA5A5A500,
    0x91919100, 0x1F1F1F00, 0x05050500, 0x95959500, 0x74747400, 0xA9A9A900, 0xC1C1C100, 0x5B5B5B00,
    0x4A4A4A00, 0x85858500, 0x6D6D6D00, 0x13131300, 0x07070700, 0x4F4F4F00, 0x4E4E4E00, 0x45454500,
    0xB2B2B200, 0x0F0F0F00, 0xC9C9C900, 0x1C1C1C00, 0xA6A6A600, 0xBCBCBC00, 0xECECEC00, 0x73737300,
    0x90909000, 0x7B7B7B00, 0xCFCFCF00, 0x59595900, 0x8F8F8F00, 0xA1A1A100, 0xF9F9F900, 0x2D2D2D00,
    0xF2F2F200, 0xB1B1B100, 0x00000000, 0x94949400, 0x37373700, 0x9F9F9F00, 0xD0D0D000, 0x2E2E2E00,
    0x9C9C9C00, 0x6E6E6E00, 0x28282800, 0x3F3F3F00, 0x80808000, 0xF0F0F000, 0x3D3D3D00, 0xD3D3D300,
    0x25252500, 0x8A8A8A00, 0xB5B5B500, 0xE7E7E700, 0x42424200, 0xB3B3B300, 0xC7C7C700, 0xEAEAEA00,
    0xF7F7F700, 0x4C4C4C00, 0x11111100, 0x33333300, 0x03030300, 0xA2A2A200, 0xACACAC00, 0x60606000,
];

const SBOX1: [u32; 256] = [
    0x52520052, 0x09090009, 0x6A6A006A, 0xD5D500D5, 0x30300030, 0x36360036, 0xA5A500A5, 0x38380038,
    0xBFBF00BF, 0x40400040, 0xA3A300A3, 0x9E9E009E, 0x81810081, 0xF3F300F3, 0xD7D700D7, 0xFBFB00FB,
    0x7C7C007C, 0xE3E300E3, 0x39390039, 0x82820082, 0x9B9B009B, 0x2F2F002F, 0xFFFF00FF, 0x87870087,
    0x34340034, 0x8E8E008E, 0x43430043, 0x44440044, 0xC4C400C4, 0xDEDE00DE, 0xE9E900E9, 0xCBCB00CB,
    0x54540054, 0x7B7B007B, 0x94940094, 0x32320032, 0xA6A600A6, 0xC2C200C2, 0x23230023, 0x3D3D003D,
    0xEEEE00EE, 0x4C4C004C, 0x95950095, 0x0B0B000B, 0x42420042, 0xFAFA00FA, 0xC3C300C3, 0x4E4E004E,
    0x08080008, 0x2E2E002E, 0xA1A100A1, 0x66660066, 0x28280028, 0xD9D900D9, 0x24240024, 0xB2B200B2,
    0x76760076, 0x5B5B005B, 0xA2A200A2, 0x49490049, 0x6D6D006D, 0x8B8B008B, 0xD1D100D1, 0x25250025,
    0x72720072, 0xF8F800F8, 0xF6F600F6, 0x64640064, 0x86860086, 0x68680068, 0x98980098, 0x16160016,
    0xD4D400D4, 0xA4A400A4, 0x5C5C005C, 0xCCCC00CC, 0x5D5D005D, 0x65650065, 0xB6B600B6, 0x92920092,
    0x6C6C006C, 0x70700070, 0x48480048, 0x50500050, 0xFDFD00FD, 0xEDED00ED, 0xB9B900B9, 0xDADA00DA,
    0x5E5E005E, 0x15150015, 0x46460046, 0x57570057, 0xA7A700A7, 0x8D8D008D, 0x9D9D009D, 0x84840084,
    0x90900090, 0xD8D800D8, 0xABAB00AB, 0x00000000, 0x8C8C008C, 0xBCBC00BC, 0xD3D300D3, 0x0A0A000A,
    0xF7F700F7, 0xE4E400E4, 0x58580058, 0x05050005, 0xB8B800B8, 0xB3B300B3, 0x45450045, 0x06060006,
    0xD0D000D0, 0x2C2C002C, 0x1E1E001E, 0x8F8F008F, 0xCACA00CA, 0x3F3F003F, 0x0F0F000F, 0x02020002,
    0xC1C100C1, 0xAFAF00AF, 0xBDBD00BD, 0x03030003, 0x01010001, 0x13130013, 0x8A8A008A, 0x6B6B006B,
    0x3A3A003A, 0x91910091, 0x11110011, 0x41410041, 0x4F4F004F, 0x67670067, 0xDCDC00DC, 0xEAEA00EA,
    0x97970097, 0xF2F200F2, 0xCFCF00CF, 0xCECE00CE, 0xF0F000F0, 0xB4B400B4, 0xE6E600E6, 0x73730073,
    0x96960096, 0xACAC00AC, 0x74740074, 0x22220022, 0xE7E700E7, 0xADAD00AD, 0x35350035, 0x85850085,
    0xE2E200E2, 0xF9F900F9, 0x37370037, 0xE8E800E8, 0x1C1C001C, 0x75750075, 0xDFDF00DF, 0x6E6E006E,
    0x47470047, 0xF1F100F1, 0x1A1A001A, 0x71710071, 0x1D1D001D, 0x29290029, 0xC5C500C5, 0x89890089,
    0x6F6F006F, 0xB7B700B7, 0x62620062, 0x0E0E000E, 0xAAAA00AA, 0x18180018, 0xBEBE00BE, 0x1B1B001B,
    0xFCFC00FC, 0x56560056, 0x3E3E003E, 0x4B4B004B, 0xC6C600C6, 0xD2D200D2, 0x79790079, 0x20200020,
    0x9A9A009A, 0xDBDB00DB, 0xC0C000C0, 0xFEFE00FE, 0x78780078, 0xCDCD00CD, 0x5A5A005A, 0xF4F400F4,
    0x1F1F001F, 0xDDDD00DD, 0xA8A800A8, 0x33330033, 0x88880088, 0x07070007, 0xC7C700C7, 0x31310031,
    0xB1B100B1, 0x12120012, 0x10100010, 0x59590059, 0x27270027, 0x80800080, 0xECEC00EC, 0x5F5F005F,
    0x60600060, 0x51510051, 0x7F7F007F, 0xA9A900A9, 0x19190019, 0xB5B500B5, 0x4A4A004A, 0x0D0D000D,
    0x2D2D002D, 0xE5E500E5, 0x7A7A007A, 0x9F9F009F, 0x93930093, 0xC9C900C9, 0x9C9C009C, 0xEFEF00EF,
    0xA0A000A0, 0xE0E000E0, 0x3B3B003B, 0x4D4D004D, 0xAEAE00AE, 0x2A2A002A, 0xF5F500F5, 0xB0B000B0,
    0xC8C800C8, 0xEBEB00EB, 0xBBBB00BB, 0x3C3C003C, 0x83830083, 0x53530053, 0x99990099, 0x61610061,
    0x17170017, 0x2B2B002B, 0x04040004, 0x7E7E007E, 0xBABA00BA, 0x77770077, 0xD6D600D6, 0x26260026,
    0xE1E100E1, 0x69690069, 0x14140014, 0x63630063, 0x55550055, 0x21210021, 0x0C0C000C, 0x077D007D,
];

const SBOX2: [u32; 256] = [
    0xE200E2E2, 0x4E004E4E, 0x54005454, 0xFC00FCFC, 0x94009494, 0xC200C2C2, 0x4A004A4A, 0xCC00CCCC,
    0x62006262, 0x0D000D0D, 0x6A006A6A, 0x46004646, 0x3C003C3C, 0x4D004D4D, 0x8B008B8B, 0xD100D1D1,
    0x5E005E5E, 0xFA00FAFA, 0x64006464, 0xCB00CBCB, 0xB400B4B4, 0x97009797, 0xBE00BEBE, 0x2B002B2B,
    0xBC00BCBC, 0x77007777, 0x2E002E2E, 0x03000303, 0xD300D3D3, 0x19001919, 0x59005959, 0xC100C1C1,
    0x1D001D1D, 0x06000606, 0x41004141, 0x6B006B6B, 0x55005555, 0xF000F0F0, 0x99009999, 0x69006969,
    0xEA00EAEA, 0x9C009C9C, 0x18001818, 0xAE00AEAE, 0x63006363, 0xDF00DFDF, 0xE700E7E7, 0xBB00BBBB,
    0x00000000, 0x73007373, 0x66006666, 0xFB00FBFB, 0x96009696, 0x4C004C4C, 0x85008585, 0xE400E4E4,
    0x3A003A3A, 0x09000909, 0x45004545, 0xAA00AAAA, 0x0F000F0F, 0xEE00EEEE, 0x10001010, 0xEB00EBEB,
    0x2D002D2D, 0x7F007F7F, 0xF400F4F4, 0x29002929, 0xAC00ACAC, 0xCF00CFCF, 0xAD00ADAD, 0x91009191,
    0x8D008D8D, 0x78007878, 0xC800C8C8, 0x95009595, 0xF900F9F9, 0x2F002F2F, 0xCE00CECE, 0xCD00CDCD,
    0x08000808, 0x7A007A7A, 0x88008888, 0x38003838, 0x5C005C5C, 0x83008383, 0x2A002A2A, 0x28002828,
    0x47004747, 0xDB00DBDB, 0xB800B8B8, 0xC700C7C7, 0x93009393, 0xA400A4A4, 0x12001212, 0x53005353,
    0xFF00FFFF, 0x87008787, 0x0E000E0E, 0x31003131, 0x36003636, 0x21002121, 0x58005858, 0x48004848,
    0x01000101, 0x8E008E8E, 0x37003737, 0x74007474, 0x32003232, 0xCA00CACA, 0xE900E9E9, 0xB100B1B1,
    0xB700B7B7, 0xAB00ABAB, 0x0C000C0C, 0xD700D7D7, 0xC400C4C4, 0x56005656, 0x42004242, 0x26002626,
    0x07000707, 0x98009898, 0x60006060, 0xD900D9D9, 0xB600B6B6, 0xB900B9B9, 0x11001111, 0x40004040,
    0xEC00ECEC, 0x20002020, 0x8C008C8C, 0xBD00BDBD, 0xA000A0A0, 0xC900C9C9, 0x84008484, 0x4000404,
    0x49004949, 0x23002323, 0xF100F1F1, 0x4F004F4F, 0x50005050, 0x1F001F1F, 0x13001313, 0xDC00DCDC,
    0xD800D8D8, 0xC000C0C0, 0x9E009E9E, 0x57005757, 0xE300E3E3, 0xC300C3C3, 0x7B007B7B, 0x65006565,
    0x3B003B3B, 0x02000202, 0x8F008F8F, 0x3E003E3E, 0xE800E8E8, 0x25002525, 0x92009292, 0xE500E5E5,
    0x15001515, 0xDD00DDDD, 0xFD00FDFD, 0x17001717, 0xA900A9A9, 0xBF00BFBF, 0xD400D4D4, 0x9A009A9A,
    0x7E007E7E, 0xC500C5C5, 0x39003939, 0x67006767, 0xFE00FEFE, 0x76007676, 0x9D009D9D, 0x43004343,
    0xA700A7A7, 0xE100E1E1, 0xD000D0D0, 0xF500F5F5, 0x68006868, 0xF200F2F2, 0x1B001B1B, 0x34003434,
    0x70007070, 0x05000505, 0xA300A3A3, 0x8A008A8A, 0xD500D5D5, 0x79007979, 0x86008686, 0xA800A8A8,
    0x30003030, 0xC600C6C6, 0x51005151, 0x4B004B4B, 0x1E001E1E, 0xA600A6A6, 0x27002727, 0xF600F6F6,
    0x35003535, 0xD200D2D2, 0x6E006E6E, 0x24002424, 0x16001616, 0x82008282, 0x5F005F5F, 0xDA00DADA,
    0xE600E6E6, 0x75007575, 0xA200A2A2, 0xEF00EFEF, 0x2C002C2C, 0xB200B2B2, 0x1C001C1C, 0x9F009F9F,
    0x5D005D5D, 0x6F006F6F, 0x80008080, 0x0A000A0A, 0x72007272, 0x44004444, 0x9B009B9B, 0x6C006C6C,
    0x90009090, 0x0B000B0B, 0x5B005B5B, 0x33003333, 0x7D007D7D, 0x5A005A5A, 0x52005252, 0xF300F3F3,
    0x61006161, 0xA100A1A1, 0xF700F7F7, 0xB000B0B0, 0xD600D6D6, 0x3F003F3F, 0x7C007C7C, 0x6D006D6D,
    0xED00EDED, 0x14001414, 0xE000E0E0, 0xA500A5A5, 0x3D003D3D, 0x22002222, 0xB300B3B3, 0xF800F8F8,
    0x89008989, 0xDE00DEDE, 0x71007171, 0x1A001A1A, 0xAF00AFAF, 0xBA00BABA, 0xB500B5B5, 0x81008181,
];

const SBOX3: [u32; 256] = [
    0x00636363, 0x007C7C7C, 0x00777777, 0x007B7B7B, 0x00F2F2F2, 0x006B6B6B, 0x006F6F6F, 0x00C5C5C5,
    0x00303030, 0x00010101, 0x00676767, 0x002B2B2B, 0x00FEFEFE, 0x00D7D7D7, 0x00ABABAB, 0x00767676,
    0x00CACACA, 0x00828282, 0x00C9C9C9, 0x007D7D7D, 0x00FAFAFA, 0x00595959, 0x00474747, 0x00F0F0F0,
    0x00ADADAD, 0x00D4D4D4, 0x00A2A2A2, 0x00AFAFAF, 0x009C9C9C, 0x00A4A4A4, 0x00727272, 0x00C0C0C0,
    0x00B7B7B7, 0x00FDFDFD, 0x00939393, 0x00262626, 0x00363636, 0x003F3F3F, 0x00F7F7F7, 0x00CCCCCC,
    0x00343434, 0x00A5A5A5, 0x00E5E5E5, 0x00F1F1F1, 0x00717171, 0x00D8D8D8, 0x00313131, 0x00151515,
    0x00040404, 0x00C7C7C7, 0x00232323, 0x00C3C3C3, 0x00181818, 0x00969696, 0x00050505, 0x009A9A9A,
    0x00070707, 0x00121212, 0x00808080, 0x00E2E2E2, 0x00EBEBEB, 0x00272727, 0x00B2B2B2, 0x00757575,
    0x00090909, 0x00838383, 0x002C2C2C, 0x001A1A1A, 0x001B1B1B, 0x006E6E6E, 0x005A5A5A, 0x00A0A0A0,
    0x00525252, 0x003B3B3B, 0x00D6D6D6, 0x00B3B3B3, 0x00292929, 0x00E3E3E3, 0x002F2F2F, 0x00848484,
    0x00535353, 0x00D1D1D1, 0x00000000, 0x00EDEDED, 0x00202020, 0x00FCFCFC, 0x00B1B1B1, 0x005B5B5B,
    0x006A6A6A, 0x00CBCBCB, 0x00BEBEBE, 0x00393939, 0x004A4A4A, 0x004C4C4C, 0x00585858, 0x00CFCFCF,
    0x00D0D0D0, 0x00EFEFEF, 0x00AAAAAA, 0x00FBFBFB, 0x00434343, 0x004D4D4D, 0x00333333, 0x00858585,
    0x00454545, 0x00F9F9F9, 0x00020202, 0x007F7F7F, 0x00505050, 0x003C3C3C, 0x009F9F9F, 0x00A8A8A8,
    0x00515151, 0x00A3A3A3, 0x00404040, 0x008F8F8F, 0x00929292, 0x009D9D9D, 0x00383838, 0x00F5F5F5,
    0x00BCBCBC, 0x00B6B6B6, 0x00DADADA, 0x00212121, 0x00101010, 0x00FFFFFF, 0x00F3F3F3, 0x00D2D2D2,
    0x00CDCDCD, 0x000C0C0C, 0x00131313, 0x00ECECEC, 0x005F5F5F, 0x00979797, 0x00444444, 0x00171717,
    0x00C4C4C4, 0x00A7A7A7, 0x007E7E7E, 0x003D3D3D, 0x00646464, 0x005D5D5D, 0x00191919, 0x00737373,
    0x00606060, 0x00818181, 0x004F4F4F, 0x00DCDCDC, 0x00222222, 0x002A2A2A, 0x00909090, 0x00888888,
    0x00464646, 0x00EEEEEE, 0x00B8B8B8, 0x00141414, 0x00DEDEDE, 0x005E5E5E, 0x000B0B0B, 0x00DBDBDB,
    0x00E0E0E0, 0x00323232, 0x003A3A3A, 0x000A0A0A, 0x00494949, 0x00060606, 0x00242424, 0x005C5C5C,
    0x00C2C2C2, 0x00D3D3D3, 0x00ACACAC, 0x00626262, 0x00919191, 0x00959595, 0x00E4E4E4, 0x00797979,
    0x00E7E7E7, 0x00C8C8C8, 0x00373737, 0x006D6D6D, 0x008D8D8D, 0x00D5D5D5, 0x004E4E4E, 0x00A9A9A9,
    0x006C6C6C, 0x00565656, 0x00F4F4F4, 0x00EAEAEA, 0x00656565, 0x007A7A7A, 0x00AEAEAE, 0x00080808,
    0x00BABABA, 0x00787878, 0x00252525, 0x002E2E2E, 0x001C1C1C, 0x00A6A6A6, 0x00B4B4B4, 0x00C6C6C6,
    0x00E8E8E8, 0x00DDDDDD, 0x00747474, 0x001F1F1F, 0x004B4B4B, 0x00BDBDBD, 0x008B8B8B, 0x008A8A8A,
    0x00707070, 0x003E3E3E, 0x00B5B5B5, 0x00666666, 0x00484848, 0x00030303, 0x00F6F6F6, 0x000E0E0E,
    0x00616161, 0x00353535, 0x00575757, 0x00B9B9B9, 0x00868686, 0x00C1C1C1, 0x001D1D1D, 0x009E9E9E,
    0x00E1E1E1, 0x00F8F8F8, 0x00989898, 0x00111111, 0x00696969, 0x00D9D9D9, 0x008E8E8E, 0x00949494,
    0x009B9B9B, 0x001E1E1E, 0x00878787, 0x00E9E9E9, 0x00CECECE, 0x00555555, 0x00282828, 0x00DFDFDF,
    0x008C8C8C, 0x00A1A1A1, 0x00898989, 0x000D0D0D, 0x00BFBFBF, 0x00E6E6E6, 0x00424242, 0x00686868,
    0x00414141, 0x00999999, 0x002D2D2D, 0x000F0F0F, 0x00B0B0B0, 0x00545454, 0x00BBBBBB, 0x00161616,
];

fn byte0(row: u32) -> u8 {
    (row & 0xFF) as u8
}
fn byte1(row: u32) -> u8 {
    ((row >> 0x08) & 0xFF) as u8
}
fn byte2(row: u32) -> u8 {
    ((row >> 0x10) & 0xFF) as u8
}
fn byte3(row: u32) -> u8 {
    ((row >> 0x18) & 0xFF) as u8
}

fn btshift2(row: u32) -> u32 {
    (row >> 0x10) | (row << 0x10)
}
fn btshiftr1(row: u32) -> u32 {
    (row << 0x18) | (row >> 0x8)
}
fn btshuffle(row: u32) -> u32 {
    ((row & 0xff00ff) << 8) | ((row >> 8) & 0xff00ff)
}
fn btrev(row: u32) -> u32 {
    row.swap_bytes()
}
fn btrow(bytes: [u8; 4]) -> u32 {
    u32::from_ne_bytes(bytes)
}

fn adv3(val: u32) -> u32 {
    (val + 1) % 3
}

pub enum NumRounds {
    R16,
    R14,
    R12,
}

pub struct Key([u32; 8]);

pub type Block = [u8; 16];

#[allow(non_snake_case)]
pub mod BlockUtil {
    use super::*;

    pub fn from_bytes<const N: usize>(bytes: &[u8]) -> [Block; N] {
        let mut vec = bytes.to_vec();
        vec.resize(N * 16, 0u8);
        let blocks = vec.as_slice().as_slice_of::<Block>().unwrap();
        blocks.try_into().unwrap()
    }

    pub fn from_str<const N: usize>(str: &str) -> [Block; N] {
        from_bytes(str.as_bytes())
    }

    pub fn one_from_bytes(bytes: &[u8]) -> Block {
        from_bytes::<1>(bytes)[0]
    }

    pub fn one_from_str(str: &str) -> Block {
        from_str::<1>(str)[0]
    }

    pub fn as_bytes(blocks: &[Block]) -> &[u8] {
        blocks.as_byte_slice()
    }

    pub fn try_as_utf8_string(blocks: &[Block]) -> Result<&str, std::str::Utf8Error>  {
        std::str::from_utf8(as_bytes(blocks))
    }
}

impl Key {
    pub fn expand(&self, num_rounds: NumRounds) -> ExpandedKey {
        let mut expkey = match &num_rounds {
            NumRounds::R16 => ExpandedKey::R16([0u32; 0x44]),
            NumRounds::R14 => ExpandedKey::R14([0u32; 0x3c]),
            NumRounds::R12 => ExpandedKey::R12([0u32; 0x34]),
        };

        let mut rcon_seed = match &num_rounds {
            NumRounds::R16 => 1,
            NumRounds::R14 => 0,
            NumRounds::R12 => 2,
        };

        let expkey_slice = expkey.as_mut_slice();

        let mut state = self.0.map(btrev);

        for r in 0..4 {
            let (s0, s1) = state.split_at_mut(4);
            let inkey;
            let outkey;
            if r % 2 == 0 {
                inkey = s0;
                outkey = s1;
            } else {
                inkey = s1;
                outkey = s0;
            }

            rcon_seed = adv3(rcon_seed);

            let xor = outkey;
            if r == 3 {
                for (i, xorrow) in xor.iter_mut().enumerate() {
                    *xorrow = btrev(self.0[i]);
                }
            } else {
                let mut tmpkey = [0u32; 4];
                for i in 0..4 {
                    let mut row = inkey[i] ^ RCON[(rcon_seed * 4 + i as u32) as usize];
                    if r % 2 == 1 {
                        row = btshift2(row);
                    }
                    tmpkey[i] = unsafe {
                        SBOX0.get_unchecked(byte0(row) as usize)
                            ^ SBOX1.get_unchecked(byte1(row) as usize)
                            ^ SBOX2.get_unchecked(byte2(row) as usize)
                            ^ SBOX3.get_unchecked(byte3(row) as usize)
                    };
                }

                let mut tmp = [0u32; 4];
                if r % 2 == 1 {
                    tmp[0] = btshift2(tmpkey[0] ^ tmpkey[1] ^ tmpkey[2]);
                    tmp[1] = tmpkey[0] ^ tmpkey[1] ^ tmpkey[3];
                    tmp[2] = btrev(tmpkey[0] ^ tmpkey[2] ^ tmpkey[3]);
                    tmp[3] = btshuffle(tmpkey[1] ^ tmpkey[2] ^ tmpkey[3]);
                } else {
                    tmp[0] = tmpkey[0] ^ tmpkey[1] ^ tmpkey[2];
                    tmp[1] = btshift2(tmpkey[0] ^ tmpkey[1] ^ tmpkey[3]);
                    tmp[2] = btshuffle(tmpkey[0] ^ tmpkey[2] ^ tmpkey[3]);
                    tmp[3] = btrev(tmpkey[1] ^ tmpkey[2] ^ tmpkey[3]);
                }

                xor[0] ^= tmp[0] ^ tmp[1] ^ tmp[2];
                xor[1] ^= tmp[0] ^ tmp[1] ^ tmp[3];
                xor[2] ^= tmp[0] ^ tmp[2] ^ tmp[3];
                xor[3] ^= tmp[1] ^ tmp[2] ^ tmp[3];
            }

            for i in 0..4 {
                let dst = &mut expkey_slice[r * 4 + i..];
                dst[0x0] = inkey[i] ^ (xor[i] >> 19) ^ (xor[(3 + i) % 4] << 13);
                dst[0x10] = inkey[i] ^ xor[i] >> 31 ^ xor[(3 + i) % 4] << 1;
                dst[0x20] = inkey[i] ^ xor[(2 + i) % 4] >> 3 ^ xor[(1 + i) % 4] << 29;
                if dst.len() > 0x30 {
                    dst[0x30] = inkey[i] ^ xor[(1 + i) % 4] >> 1 ^ xor[i] << 31;
                }
                if dst.len() > 0x40 {
                    dst[0x40] = inkey[i] ^ xor[(1 + i) % 4] >> 13 ^ xor[i] << 19;
                }
            }
        }

        expkey
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_byte_slice()
    }
}

impl From<[u8; 32]> for Key {
    fn from(data: [u8; 32]) -> Self {
        let data: &[u32] = data.as_slice_of().unwrap();
        let data: [u32; 8] = data.try_into().unwrap();

        Self(data)
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum ExpandedKey {
    R16([u32; 0x44]),
    R14([u32; 0x3c]),
    R12([u32; 0x34]),
}

impl ExpandedKey {
    pub fn num_rounds(&self) -> usize {
        match &self {
            ExpandedKey::R16(..) => 16,
            ExpandedKey::R14(..) => 14,
            ExpandedKey::R12(..) => 12,
        }
    }

    pub fn as_slice(&self) -> &[u32] {
        match self {
            ExpandedKey::R16(s) => s,
            ExpandedKey::R14(s) => s,
            ExpandedKey::R12(s) => s,
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u32] {
        match self {
            ExpandedKey::R16(s) => s,
            ExpandedKey::R14(s) => s,
            ExpandedKey::R12(s) => s,
        }
    }

    pub fn encrypt_one(&self, data: &Block) -> Block {
        let data: &[u32] = data.as_slice_of().unwrap();
        let data: &[u32; 4] = data.try_into().unwrap();
        let encrypted = crypt_block(data, self);
        encrypted.as_byte_slice().try_into().unwrap()
    }

    pub fn encrypt<const N: usize>(&self, data: &[Block; N]) -> [Block; N] {
        data.map(|c| self.encrypt_one(&c))
    }

    pub fn mut_encrypt(&self, data: &mut [Block]) {
        data.iter_mut().for_each(|c| {
            let tmp = self.encrypt_one(c);
            c.copy_from_slice(&tmp)
        });
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct DecryptKey {
    expkey: ExpandedKey,
}

impl DecryptKey {
    pub fn decrypt_one(&self, data: &Block) -> Block {
        let data: &[u32] = data.as_slice_of().unwrap();
        let data: &[u32; 4] = data.try_into().unwrap();
        let encrypted = crypt_block(data, &self.expkey);
        encrypted.as_byte_slice().try_into().unwrap()
    }

    pub fn decrypt<const N: usize>(&self, data: &[Block; N]) -> [Block; N] {
        data.map(|c| self.decrypt_one(&c))
    }

    pub fn mut_decrypt(&self, data: &mut [Block]) {
        data.iter_mut().for_each(|c| {
            let tmp = self.decrypt_one(c);
            c.copy_from_slice(&tmp)
        });
    }
}

impl From<ExpandedKey> for DecryptKey {
    fn from(mut expkey: ExpandedKey) -> Self {
        let mut blocks_iter = expkey.as_mut_slice().chunks_exact_mut(4);

        // SAFETY: the iterator has fixed size which is always greater than 2
        let p1 = unsafe { blocks_iter.next().unwrap_unchecked() };
        let p2 = unsafe { blocks_iter.next_back().unwrap_unchecked() };

        p1.swap_with_slice(p2);

        loop {
            // SAFETY: the iterator size is always odd (17, 15, or 13)
            let p1 = unsafe { blocks_iter.next().unwrap_unchecked() };

            let mix_rounds = |dst: &mut [u32], src: &[u32]| {
                let mut tmp = [0u32; 4];
                for i in 0..4 {
                    tmp[i] = btshift2(src[i] ^ btshiftr1(src[i])) ^ btshiftr1(src[i]);
                }

                let mut tmp2 = [0u32; 4];
                tmp2[0] = tmp[0] ^ tmp[1] ^ tmp[2];
                tmp2[1] = btshift2(tmp[0] ^ tmp[1] ^ tmp[3]);
                tmp2[2] = btshuffle(tmp[0] ^ tmp[2] ^ tmp[3]);
                tmp2[3] = btrev(tmp[1] ^ tmp[2] ^ tmp[3]);

                dst[0] = tmp2[0] ^ tmp2[1] ^ tmp2[2];
                dst[1] = tmp2[0] ^ tmp2[1] ^ tmp2[3];
                dst[2] = tmp2[0] ^ tmp2[2] ^ tmp2[3];
                dst[3] = tmp2[1] ^ tmp2[2] ^ tmp2[3];
            };

            if let Some(p2) = blocks_iter.next_back() {
                let p2tmp: [u32; 4] = unsafe { p2.try_into().unwrap_unchecked() };
                mix_rounds(p2, p1);
                mix_rounds(p1, &p2tmp);
            } else {
                let p1tmp: [u32; 4] = unsafe { p1.try_into().unwrap_unchecked() };
                mix_rounds(p1, &p1tmp);
                return Self { expkey };
            }
        }
    }
}

fn crypt_block(data: &[u32; 4], key: &ExpandedKey) -> [u32; 4] {
    let num_rounds = key.num_rounds();
    let mut state: [u32; 4] = [
        btrev(data[0]),
        btrev(data[1]),
        btrev(data[2]),
        btrev(data[3]),
    ];

    let mut roundkeys = key.as_slice().chunks_exact(4);
    for i in 0..num_rounds - 1 {
        // SAFETY: we're iterating through (0..num_rounds - 1), so this can never fail
        let roundkey = unsafe { roundkeys.next().unwrap_unchecked() };
        let mut sub = [0u32; 4];
        for r in 0..4 {
            let mut keyed = state[r] ^ roundkey[r];
            if i % 2 == 1 {
                keyed = btshift2(keyed);
            }
            sub[r] = unsafe {
                SBOX0.get_unchecked(byte0(keyed) as usize)
                    ^ SBOX1.get_unchecked(byte1(keyed) as usize)
                    ^ SBOX2.get_unchecked(byte2(keyed) as usize)
                    ^ SBOX3.get_unchecked(byte3(keyed) as usize)
            };
        }

        let mut mix = [0u32; 4];
        if i % 2 == 1 {
            mix[0] = btshift2(sub[0] ^ sub[1] ^ sub[2]);
            mix[1] = sub[0] ^ sub[1] ^ sub[3];
            mix[2] = btrev(sub[0] ^ sub[2] ^ sub[3]);
            mix[3] = btshuffle(sub[1] ^ sub[2] ^ sub[3]);
        } else {
            mix[0] = sub[0] ^ sub[1] ^ sub[2];
            mix[1] = btshift2(sub[0] ^ sub[1] ^ sub[3]);
            mix[2] = btshuffle(sub[0] ^ sub[2] ^ sub[3]);
            mix[3] = btrev(sub[1] ^ sub[2] ^ sub[3]);
        }

        state[0] = mix[0] ^ mix[1] ^ mix[2];
        state[1] = mix[0] ^ mix[1] ^ mix[3];
        state[2] = mix[0] ^ mix[2] ^ mix[3];
        state[3] = mix[1] ^ mix[2] ^ mix[3];
    }

    // SAFETY: we've iterated through (0..num_rounds - 1), and now we get
    // the last two entries (there's always one more than num_rounds), so
    // this can never fail
    let roundkey1 = unsafe { roundkeys.next().unwrap_unchecked() };
    let roundkey2 = unsafe { roundkeys.next().unwrap_unchecked() };

    let mut ret = [0u32; 4];
    for i in 0..4 {
        let keyed = btshift2(state[i] ^ roundkey1[i]);
        let sub = btrow(unsafe {
            [
                *SBOX1.get_unchecked(byte1(keyed) as usize) as u8,
                (*SBOX0.get_unchecked(byte0(keyed) as usize) >> 8) as u8,
                *SBOX3.get_unchecked(byte3(keyed) as usize) as u8,
                *SBOX2.get_unchecked(byte2(keyed) as usize) as u8,
            ]
        });

        ret[i] = sub ^ btrev(roundkey2[i]);
    }

    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_key_expand() {
        let key = Key([0x67496975, 0x69735552, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]);
        let expkey = key.expand(NumRounds::R16);

        let expected = ExpandedKey::R16([
            0x7a03dff8, 0x9e945f05, 0x8608bd45, 0xe87f9980, 0x6cf0f59b, 0x7f587662, 0x26ae8be8,
            0x6cab644b, 0xcbfb3cd5, 0x2611b1a9, 0x57cf9421, 0x1200da0e, 0xe9b8b7d3, 0x8414511e,
            0x25a277f0, 0xd3d2bb5e, 0xed69bfce, 0x3ba9bf7b, 0xc6c8608b, 0xd45e87f9, 0x4503e6e0,
            0x5a45f381, 0x88538be0, 0x4d4a71e5, 0x3b35975f, 0xe24f16f3, 0x1ad473f1, 0xef606f95,
            0xe9b8b97e, 0x47ea299a, 0x2f65b122, 0xd3d2bb5e, 0xc82ca118, 0xcbd57c03, 0x969fccc1,
            0x2c6c8608, 0x7ceac6a2, 0x7c7be84b, 0x79bd5fc0, 0x8a27b7d5, 0x0de90b1c, 0x2b443365,
            0x9d921277, 0x2d59d71e, 0xc9b8b97e, 0xad38bb54, 0x85627edc, 0x39981533, 0xc4db5145,
            0xa742d297, 0x66003daa, 0x5a7f3304, 0xac61540e, 0x4336b2e9, 0x965023c6, 0x82480ba5,
            0xca0cbc48, 0x74d9cff6, 0x294c58f7, 0x8c229ccb, 0x409200ca, 0x2d38bb54, 0x8bcf57f0,
            0xe9661fed, 0x45225246, 0xd07a2213, 0x1fe66003, 0xdaa5a7f3,
        ]);
        assert_eq!(expkey, expected);
    }

    #[test]
    fn basic_key_derive() {
        let key = Key([
            0x66466571, 0x65787949, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000,
        ]);
        let expkey = key.expand(NumRounds::R16);
        let deckey: DecryptKey = expkey.into();

        let expected = ExpandedKey::R16([
            0xdaa50a3d, 0x56a0c4b4, 0xef55754d, 0xd2f1130e, 0x7576ac6d, 0x543bd460, 0xecfc7429,
            0xbbc30fe8, 0xb94aceab, 0xb2b2dafe, 0x35c2be25, 0x8e4501f0, 0x81e5d8d3, 0x24c67e11,
            0x34675617, 0x64fb8b2a, 0xf67d4b79, 0x1836ba04, 0xc6d36581, 0xcba21907, 0xf4263a9c,
            0x1d020440, 0x5e755676, 0xaa4e55f1, 0x8774b9b8, 0x81fe00ad, 0x3237fa2b, 0x172283ed,
            0x713d6720, 0x580bde4d, 0xb4ae3364, 0xcff0ab97, 0x5d752e5d, 0xc2347e59, 0xc7a0b3c9,
            0x1462f3a6, 0xd8a7cf64, 0xce4508b0, 0xab73af60, 0xfb452a11, 0x67075b8b, 0x3dd93d72,
            0xeb69c0da, 0xb317be50, 0x66c735db, 0x2f0b8ec6, 0x0fe29300, 0xa6e6d52b, 0x4fa2627d,
            0xef9e0180, 0xa4907272, 0xcc51dab2, 0xb80f5a1b, 0xb18d4bae, 0x52fa7315, 0x67227ebe,
            0x6e3fa650, 0xd755a510, 0x2b3fdd83, 0x6e36715c, 0x943c2c1e, 0xdbeeb0ef, 0xbf935956,
            0x45d938f2, 0x462e822a, 0x73d67954, 0x6c7f66f3, 0x47bd55d5,
        ]);
        assert_eq!(deckey.expkey, expected);
    }

    #[test]
    fn encode_decode_u32() {
        let key = Key([
            0x67496975, 0x69735552, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
        ]);

        let raw: Block = [
                    0x44,	0x61,	0x74,	0x61,	0x2f,	0x49,	0x74,	0x65,
                    0x6d,	0x2e,	0x73,	0x63,	0x70,	0x00,   0x00,   0x00,
        ];
        println!("raw: {raw:x?} ({})", std::str::from_utf8(&raw).unwrap());

        let expkey = key.expand(NumRounds::R16);
        println!("expkey: {expkey:x?}");

        let encoded = expkey.encrypt_one(&raw);
        println!("encoded: {:x?}", encoded.as_byte_slice());

        let deckey = DecryptKey::from(expkey);
        println!("deckey: {:x?}", deckey);

        let decoded = deckey.decrypt_one(&encoded);
        println!("decoded: {:x?} ({})", decoded.as_byte_slice(), std::str::from_utf8(decoded.as_byte_slice()).unwrap());

        assert_eq!(decoded.as_byte_slice(), raw.as_byte_slice());
    }

    #[test]
    fn encode_decode_u8() {
        let key = Key::from([
            0x75, 0x69, 0x49, 0x67, 0x52, 0x55, 0x73, 0x69,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let raw: Block = [
                    0x44,	0x61,	0x74,	0x61,	0x2f,	0x49,	0x74,	0x65,
                    0x6d,	0x2e,	0x73,	0x63,	0x70,	0x00,   0x00,   0x00,
        ];
        println!("raw: {raw:x?} ({})", std::str::from_utf8(&raw).unwrap());

        let expkey = key.expand(NumRounds::R16);

        println!("expkey: {expkey:x?}");
        let encoded = expkey.encrypt_one(&raw);
        println!("encoded: {:x?}", encoded);

        let deckey = DecryptKey::from(expkey);
        println!("deckey: {:x?}", deckey);

        let decoded = deckey.decrypt_one(&encoded);
        println!("decoded: {:x?} ({})", decoded, std::str::from_utf8(&decoded).unwrap());

        assert_eq!(decoded, raw);
    }
}
