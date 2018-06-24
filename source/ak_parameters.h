/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2010 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_parameters.h                                                                               */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_PARAMETERS_H__
#define    __AK_PARAMETERS_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hash.h>
 #include <ak_curves.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Перестановки со значениями по-умолчанию для алгоритма бесключевого хеширования.
    Определены ГОСТР Р 34.11-94, приложение А. */
 static const kbox hash_box = {
               { 4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3 },
               { 14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9 },
               { 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11 },
               { 7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3 },
               { 6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2 },
               { 4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14 },
               { 13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12 },
               { 1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12 }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Перестановки для алгоритма бесключевого хеширования ГОСТ Р 34.11-94.
    Набор параметров А компании КриптоПро. */
 static const kbox hash_box_CSPA = {
               { 10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15 },
               { 5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8 },
               { 7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13 },
               { 4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3 },
               { 7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5 },
               { 7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3 },
               { 13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11 },
               { 1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12 }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Перестановки для алгоритма бесключевого хеширования ГОСТ Р 34.11-94.
    Набор параметров средства ВербаО. */
 static const kbox hash_box_VerbaO = {
               { 3, 6, 7, 8, 2, 5, 12, 14, 9, 13, 0, 10, 1, 11, 4, 15 },
               { 1, 13, 6, 2, 9, 10, 4, 3, 7, 14, 5, 11, 12, 0, 15, 8 },
               { 7, 15, 12, 3, 0, 13, 10, 5, 14, 9, 11, 2, 4, 1, 6, 8 },
               { 11, 4, 9, 1, 6, 8, 13, 10, 0, 3, 7, 14, 5, 12, 15, 2 },
               { 3, 15, 10, 0, 2, 5, 11, 6, 9, 14, 1, 8, 13, 12, 7, 4 },
               { 13, 9, 4, 11, 7, 12, 8, 3, 10, 2, 1, 15, 5, 6, 0, 14 },
               { 1, 4, 9, 3, 10, 0, 15, 2, 7, 12, 11, 13, 14, 6, 8, 5 },
               { 4, 10, 8, 11, 1, 13, 14, 6, 9, 2, 12, 15, 7, 0, 5, 3 }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Нелинейное биективное преобразование байт (алгоритмы Стрибог и Кузнечик). */
 const static ak_uint8 gost_pi[256] = {
   0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
   0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
   0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
   0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
   0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
   0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
   0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
   0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
   0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
   0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
   0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
   0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
   0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
   0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
   0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
   0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
 };

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Обратная нелинейная перестановка алгоритма Кузнечик (ГОСТ Р 34.12-2015) */
 const static ak_uint8 gost_pinv[256] = {
   0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0, 0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
   0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18, 0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
   0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4, 0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
   0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9, 0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
   0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B, 0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
   0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F, 0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
   0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2, 0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
   0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11, 0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
   0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F, 0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
   0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1, 0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
   0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0, 0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
   0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D, 0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
   0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67, 0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
   0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88, 0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
   0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
   0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7, 0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Итерационные константы (алгоритм Стрибог). */
 static const ak_uint64 streebog_c[12][8] = {
  { 0xdd806559f2a64507, 0x05767436cc744d23, 0xa2422a08a460d315, 0x4b7ce09192676901,
    0x714eb88d7585c4fc, 0x2f6a76432e45d016, 0xebcb2f81c0657c1f, 0xb1085bda1ecadae9 },
  { 0xe679047021b19bb7, 0x55dda21bd7cbcd56, 0x5cb561c2db0aa7ca, 0x9ab5176b12d69958,
    0x61d55e0f16b50131, 0xf3feea720a232b98, 0x4fe39d460f70b5d7, 0x6fa3b58aa99d2f1a },
  { 0x991e96f50aba0ab2, 0xc2b6f443867adb31, 0xc1c93a376062db09, 0xd3e20fe490359eb1,
    0xf2ea7514b1297b7b, 0x06f15e5f529c1f8b, 0x0a39fc286a3d8435, 0xf574dcac2bce2fc7 },
  { 0x220cbebc84e3d12e, 0x3453eaa193e837f1, 0xd8b71333935203be, 0xa9d72c82ed03d675,
    0x9d721cad685e353f, 0x488e857e335c3c7d, 0xf948e1a05d71e4dd, 0xef1fdfb3e81566d2 },
  { 0x601758fd7c6cfe57, 0x7a56a27ea9ea63f5, 0xdfff00b723271a16, 0xbfcd1747253af5a3,
    0x359e35d7800fffbd, 0x7f151c1f1686104a, 0x9a3f410c6ca92363, 0x4bea6bacad474799 },
  { 0xfa68407a46647d6e, 0xbf71c57236904f35, 0x0af21f66c2bec6b6, 0xcffaa6b71c9ab7b4,
    0x187f9ab49af08ec6, 0x2d66c4f95142a46c, 0x6fa4c33b7a3039c0, 0xae4faeae1d3ad3d9 },
  { 0x8886564d3a14d493, 0x3517454ca23c4af3, 0x06476983284a0504, 0x0992abc52d822c37,
    0xd3473e33197a93c9, 0x399ec6c7e6bf87c9, 0x51ac86febf240954, 0xf4c70e16eeaac5ec },
  { 0xa47f0dd4bf02e71e, 0x36acc2355951a8d9, 0x69d18d2bd1a5c42f, 0xf4892bcb929b0690,
    0x89b4443b4ddbc49a, 0x4eb7f8719c36de1e, 0x03e7aa020c6e4141, 0x9b1f5b424d93c9a7 },
  { 0x7261445183235adb, 0x0e38dc92cb1f2a60, 0x7b2b8a9aa6079c54, 0x800a440bdbb2ceb1,
    0x3cd955b7e00d0984, 0x3a7d3a1b25894224, 0x944c9ad8ec165fde, 0x378f5a541631229b },
  { 0x74b4c7fb98459ced, 0x3698fad1153bb6c3, 0x7a1e6c303b7652f4, 0x9fe76702af69334b,
    0x1fffe18a1b336103, 0x8941e71cff8a78db, 0x382ae548b2e4f3f3, 0xabbedea680056f52 },
  { 0x6bcaa4cd81f32d1b, 0xdea2594ac06fd85d, 0xefbacd1d7d476e98, 0x8a1d71efea48b9ca,
    0x2001802114846679, 0xd8fa6bbbebab0761, 0x3002c6cd635afe94, 0x7bcd9ed0efc889fb },
  { 0x48bc924af11bd720, 0xfaf417d5d9b21b99, 0xe71da4aa88e12852, 0x5d80ef9d1891cc86,
    0xf82012d430219f9b, 0xcda43c32bcdf1d77, 0xd21380b00449b17a, 0x378ee767f11631ba }
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Развернутые константы для линейного преобразования (алгоритм Стрибог). */
 static const ak_uint64 streebog_Areverse_expand[8][256] = {
{
  0x0000000000000000,  0x641c314b2b8ee083,  0xc83862965601dd1b,  0xac2453dd7d8f3d98,
  0x8d70c431ac02a736,  0xe96cf57a878c47b5,  0x4548a6a7fa037a2d,  0x215497ecd18d9aae,
  0x07e095624504536c,  0x63fca4296e8ab3ef,  0xcfd8f7f413058e77,  0xabc4c6bf388b6ef4,
  0x8a905153e906f45a,  0xee8c6018c28814d9,  0x42a833c5bf072941,  0x26b4028e9489c9c2,
  0x0edd37c48a08a6d8,  0x6ac1068fa186465b,  0xc6e55552dc097bc3,  0xa2f96419f7879b40,
  0x83adf3f5260a01ee,  0xe7b1c2be0d84e16d,  0x4b959163700bdcf5,  0x2f89a0285b853c76,
  0x093da2a6cf0cf5b4,  0x6d2193ede4821537,  0xc105c030990d28af,  0xa519f17bb283c82c,
  0x844d6697630e5282,  0xe05157dc4880b201,  0x4c750401350f8f99,  0x2869354a1e816f1a,
  0x1ca76e95091051ad,  0x78bb5fde229eb12e,  0xd49f0c035f118cb6,  0xb0833d48749f6c35,
  0x91d7aaa4a512f69b,  0xf5cb9bef8e9c1618,  0x59efc832f3132b80,  0x3df3f979d89dcb03,
  0x1b47fbf74c1402c1,  0x7f5bcabc679ae242,  0xd37f99611a15dfda,  0xb763a82a319b3f59,
  0x96373fc6e016a5f7,  0xf22b0e8dcb984574,  0x5e0f5d50b61778ec,  0x3a136c1b9d99986f,
  0x127a59518318f775,  0x7666681aa89617f6,  0xda423bc7d5192a6e,  0xbe5e0a8cfe97caed,
  0x9f0a9d602f1a5043,  0xfb16ac2b0494b0c0,  0x5732fff6791b8d58,  0x332ecebd52956ddb,
  0x159acc33c61ca419,  0x7186fd78ed92449a,  0xdda2aea5901d7902,  0xb9be9feebb939981,
  0x98ea08026a1e032f,  0xfcf639494190e3ac,  0x50d26a943c1fde34,  0x34ce5bdf17913eb7,
  0x3853dc371220a247,  0x5c4fed7c39ae42c4,  0xf06bbea144217f5c,  0x94778fea6faf9fdf,
  0xb5231806be220571,  0xd13f294d95ace5f2,  0x7d1b7a90e823d86a,  0x19074bdbc3ad38e9,
  0x3fb349555724f12b,  0x5baf781e7caa11a8,  0xf78b2bc301252c30,  0x93971a882aabccb3,
  0xb2c38d64fb26561d,  0xd6dfbc2fd0a8b69e,  0x7afbeff2ad278b06,  0x1ee7deb986a96b85,
  0x368eebf39828049f,  0x5292dab8b3a6e41c,  0xfeb68965ce29d984,  0x9aaab82ee5a73907,
  0xbbfe2fc2342aa3a9,  0xdfe21e891fa4432a,  0x73c64d54622b7eb2,  0x17da7c1f49a59e31,
  0x316e7e91dd2c57f3,  0x55724fdaf6a2b770,  0xf9561c078b2d8ae8,  0x9d4a2d4ca0a36a6b,
  0xbc1ebaa0712ef0c5,  0xd8028beb5aa01046,  0x7426d836272f2dde,  0x103ae97d0ca1cd5d,
  0x24f4b2a21b30f3ea,  0x40e883e930be1369,  0xecccd0344d312ef1,  0x88d0e17f66bfce72,
  0xa9847693b73254dc,  0xcd9847d89cbcb45f,  0x61bc1405e13389c7,  0x5a0254ecabd6944,
  0x231427c05e34a086,  0x4708168b75ba4005,  0xeb2c455608357d9d,  0x8f30741d23bb9d1e,
  0xae64e3f1f23607b0,  0xca78d2bad9b8e733,  0x665c8167a437daab,  0x240b02c8fb93a28,
  0x2a29856691385532,  0x4e35b42dbab6b5b1,  0xe211e7f0c7398829,  0x860dd6bbecb768aa,
  0xa75941573d3af204,  0xc345701c16b41287,  0x6f6123c16b3b2f1f,  0xb7d128a40b5cf9c,
  0x2dc91004d43c065e,  0x49d5214fffb2e6dd,  0xe5f17292823ddb45,  0x81ed43d9a9b33bc6,
  0xa0b9d435783ea168,  0xc4a5e57e53b041eb,  0x6881b6a32e3f7c73,  0xc9d87e805b19cf0,
  0x70a6a56e2440598e,  0x14ba94250fceb90d,  0xb89ec7f872418495,  0xdc82f6b359cf6416,
  0xfdd6615f8842feb8,  0x99ca5014a3cc1e3b,  0x35ee03c9de4323a3,  0x51f23282f5cdc320,
  0x7746300c61440ae2,  0x135a01474acaea61,  0xbf7e529a3745d7f9,  0xdb6263d11ccb377a,
  0xfa36f43dcd46add4,  0x9e2ac576e6c84d57,  0x320e96ab9b4770cf,  0x5612a7e0b0c9904c,
  0x7e7b92aaae48ff56,  0x1a67a3e185c61fd5,  0xb643f03cf849224d,  0xd25fc177d3c7c2ce,
  0xf30b569b024a5860,  0x971767d029c4b8e3,  0x3b33340d544b857b,  0x5f2f05467fc565f8,
  0x799b07c8eb4cac3a,  0x1d873683c0c24cb9,  0xb1a3655ebd4d7121,  0xd5bf541596c391a2,
  0xf4ebc3f9474e0b0c,  0x90f7f2b26cc0eb8f,  0x3cd3a16f114fd617,  0x58cf90243ac13694,
  0x6c01cbfb2d500823,  0x81dfab006dee8a0,  0xa439a96d7b51d538,  0xc025982650df35bb,
  0xe1710fca8152af15,  0x856d3e81aadc4f96,  0x29496d5cd753720e,  0x4d555c17fcdd928d,
  0x6be15e9968545b4f,  0xffd6fd243dabbcc,  0xa3d93c0f3e558654,  0xc7c50d4415db66d7,
  0xe6919aa8c456fc79,  0x828dabe3efd81cfa,  0x2ea9f83e92572162,  0x4ab5c975b9d9c1e1,
  0x62dcfc3fa758aefb,  0x6c0cd748cd64e78,  0xaae49ea9f15973e0,  0xcef8afe2dad79363,
  0xefac380e0b5a09cd,  0x8bb0094520d4e94e,  0x27945a985d5bd4d6,  0x43886bd376d53455,
  0x653c695de25cfd97,  0x1205816c9d21d14,  0xad040bcbb45d208c,  0xc9183a809fd3c00f,
  0xe84cad6c4e5e5aa1,  0x8c509c2765d0ba22,  0x2074cffa185f87ba,  0x4468feb133d16739,
  0x48f579593660fbc9,  0x2ce948121dee1b4a,  0x80cd1bcf606126d2,  0xe4d12a844befc651,
  0xc585bd689a625cff,  0xa1998c23b1ecbc7c,  0xdbddffecc6381e4,  0x69a1eeb5e7ed6167,
  0x4f15ec3b7364a8a5,  0x2b09dd7058ea4826,  0x872d8ead256575be,  0xe331bfe60eeb953d,
  0xc265280adf660f93,  0xa6791941f4e8ef10,  0xa5d4a9c8967d288,  0x6e417bd7a2e9320b,
  0x46284e9dbc685d11,  0x22347fd697e6bd92,  0x8e102c0bea69800a,  0xea0c1d40c1e76089,
  0xcb588aac106afa27,  0xaf44bbe73be41aa4,  0x360e83a466b273c,  0x677cd9716de5c7bf,
  0x41c8dbfff96c0e7d,  0x25d4eab4d2e2eefe,  0x89f0b969af6dd366,  0xedec882284e333e5,
  0xccb81fce556ea94b,  0xa8a42e857ee049c8,  0x4807d58036f7450,  0x609c4c1328e194d3,
  0x545217cc3f70aa64,  0x304e268714fe4ae7,  0x9c6a755a6971777f,  0xf876441142ff97fc,
  0xd922d3fd93720d52,  0xbd3ee2b6b8fcedd1,  0x111ab16bc573d049,  0x75068020eefd30ca,
  0x53b282ae7a74f908,  0x37aeb3e551fa198b,  0x9b8ae0382c752413,  0xff96d17307fbc490,
  0xdec2469fd6765e3e,  0xbade77d4fdf8bebd,  0x16fa240980778325,  0x72e61542abf963a6,
  0x5a8f2008b5780cbc,  0x3e9311439ef6ec3f,  0x92b7429ee379d1a7,  0xf6ab73d5c8f73124,
  0xd7ffe439197aab8a,  0xb3e3d57232f44b09,  0x1fc786af4f7b7691,  0x7bdbb7e464f59612,
  0x5d6fb56af07c5fd0,  0x39738421dbf2bf53,  0x9557d7fca67d82cb,  0xf14be6b78df36248,
  0xd01f715b5c7ef8e6,  0xb403401077f01865,  0x182713cd0a7f25fd,  0x7c3b228621f1c57e,
  },{
  0x0000000000000000,  0xa48b474f9ef5dc18,  0x550b8e9e21f7a530,  0xf180c9d1bf027928,
  0xaa16012142f35760,  0xe9d466edc068b78,  0xff1d8fbf6304f250,  0x5b96c8f0fdf12e48,
  0x492c024284fbaec0,  0xeda7450d1a0e72d8,  0x1c278cdca50c0bf0,  0xb8accb933bf9d7e8,
  0xe33a0363c608f9a0,  0x47b1442c58fd25b8,  0xb6318dfde7ff5c90,  0x12bacab2790a8088,
  0x9258048415eb419d,  0x36d343cb8b1e9d85,  0xc7538a1a341ce4ad,  0x63d8cd55aae938b5,
  0x384e05a5571816fd,  0x9cc542eac9edcae5,  0x6d458b3b76efb3cd,  0xc9cecc74e81a6fd5,
  0xdb7406c69110ef5d,  0x7fff41890fe53345,  0x8e7f8858b0e74a6d,  0x2af4cf172e129675,
  0x716207e7d3e3b83d,  0xd5e940a84d166425,  0x24698979f2141d0d,  0x80e2ce366ce1c115,
  0x39b008152acb8227,  0x9d3b4f5ab43e5e3f,  0x6cbb868b0b3c2717,  0xc830c1c495c9fb0f,
  0x93a609346838d547,  0x372d4e7bf6cd095f,  0xc6ad87aa49cf7077,  0x6226c0e5d73aac6f,
  0x709c0a57ae302ce7,  0xd4174d1830c5f0ff,  0x259784c98fc789d7,  0x811cc386113255cf,
  0xda8a0b76ecc37b87,  0x7e014c397236a79f,  0x8f8185e8cd34deb7,  0x2b0ac2a753c102af,
  0xabe80c913f20c3ba,  0xf634bdea1d51fa2,  0xfee3820f1ed7668a,  0x5a68c5408022ba92,
  0x01fe0db07dd394da,  0xa5754affe32648c2,  0x54f5832e5c2431ea,  0xf07ec461c2d1edf2,
  0xe2c40ed3bbdb6d7a,  0x464f499c252eb162,  0xb7cf804d9a2cc84a,  0x1344c70204d91452,
  0x48d20ff2f9283a1a,  0xec5948bd67dde602,  0x1dd9816cd8df9f2a,  0xb952c623462a4332,
  0x727d102a548b194e,  0xd6f65765ca7ec556,  0x27769eb4757cbc7e,  0x83fdd9fbeb896066,
  0xd86b110b16784e2e,  0x7ce05644888d9236,  0x8d609f95378feb1e,  0x29ebd8daa97a3706,
  0x3b511268d070b78e,  0x9fda55274e856b96,  0x6e5a9cf6f18712be,  0xcad1dbb96f72cea6,
  0x914713499283e0ee,  0x35cc54060c763cf6,  0xc44c9dd7b37445de,  0x60c7da982d8199c6,
  0xe02514ae416058d3,  0x44ae53e1df9584cb,  0xb52e9a306097fde3,  0x11a5dd7ffe6221fb,
  0x4a33158f03930fb3,  0xeeb852c09d66d3ab,  0x1f389b112264aa83,  0xbbb3dc5ebc91769b,
  0xa90916ecc59bf613,  0xd8251a35b6e2a0b,  0xfc029872e46c5323,  0x5889df3d7a998f3b,
  0x031f17cd8768a173,  0xa7945082199d7d6b,  0x56149953a69f0443,  0xf29fde1c386ad85b,
  0x4bcd183f7e409b69,  0xef465f70e0b54771,  0x1ec696a15fb73e59,  0xba4dd1eec142e241,
  0xe1db191e3cb3cc09,  0x45505e51a2461011,  0xb4d097801d446939,  0x105bd0cf83b1b521,
  0x02e11a7dfabb35a9,  0xa66a5d32644ee9b1,  0x57ea94e3db4c9099,  0xf361d3ac45b94c81,
  0xa8f71b5cb84862c9,  0xc7c5c1326bdbed1,  0xfdfc95c299bfc7f9,  0x5977d28d074a1be1,
  0xd9951cbb6babdaf4,  0x7d1e5bf4f55e06ec,  0x8c9e92254a5c7fc4,  0x2815d56ad4a9a3dc,
  0x73831d9a29588d94,  0xd7085ad5b7ad518c,  0x2688930408af28a4,  0x8203d44b965af4bc,
  0x90b91ef9ef507434,  0x343259b671a5a82c,  0xc5b29067cea7d104,  0x6139d72850520d1c,
  0x3aaf1fd8ada32354,  0x9e2458973356ff4c,  0x6fa491468c548664,  0xcb2fd60912a15a7c,
  0xe4fa2054a80b329c,  0x4071671b36feee84,  0xb1f1aeca89fc97ac,  0x157ae98517094bb4,
  0x4eec2175eaf865fc,  0xea67663a740db9e4,  0x1be7afebcb0fc0cc,  0xbf6ce8a455fa1cd4,
  0xadd622162cf09c5c,  0x95d6559b2054044,  0xf8ddac880d07396c,  0x5c56ebc793f2e574,
  0x07c023376e03cb3c,  0xa34b6478f0f61724,  0x52cbada94ff46e0c,  0xf640eae6d101b214,
  0x76a224d0bde07301,  0xd229639f2315af19,  0x23a9aa4e9c17d631,  0x8722ed0102e20a29,
  0xdcb425f1ff132461,  0x783f62be61e6f879,  0x89bfab6fdee48151,  0x2d34ec2040115d49,
  0x3f8e2692391bddc1,  0x9b0561dda7ee01d9,  0x6a85a80c18ec78f1,  0xce0eef438619a4e9,
  0x959827b37be88aa1,  0x311360fce51d56b9,  0xc093a92d5a1f2f91,  0x6418ee62c4eaf389,
  0xdd4a284182c0b0bb,  0x79c16f0e1c356ca3,  0x8841a6dfa337158b,  0x2ccae1903dc2c993,
  0x775c2960c033e7db,  0xd3d76e2f5ec63bc3,  0x2257a7fee1c442eb,  0x86dce0b17f319ef3,
  0x94662a03063b1e7b,  0x30ed6d4c98cec263,  0xc16da49d27ccbb4b,  0x65e6e3d2b9396753,
  0x3e702b2244c8491b,  0x9afb6c6dda3d9503,  0x6b7ba5bc653fec2b,  0xcff0e2f3fbca3033,
  0x4f122cc5972bf126,  0xeb996b8a09de2d3e,  0x1a19a25bb6dc5416,  0xbe92e5142829880e,
  0xe5042de4d5d8a646,  0x418f6aab4b2d7a5e,  0xb00fa37af42f0376,  0x1484e4356adadf6e,
  0x063e2e8713d05fe6,  0xa2b569c88d2583fe,  0x5335a0193227fad6,  0xf7bee756acd226ce,
  0xac282fa651230886,  0x8a368e9cfd6d49e,  0xf923a13870d4adb6,  0x5da8e677ee2171ae,
  0x9687307efc802bd2,  0x320c77316275f7ca,  0xc38cbee0dd778ee2,  0x6707f9af438252fa,
  0x3c91315fbe737cb2,  0x981a76102086a0aa,  0x699abfc19f84d982,  0xcd11f88e0171059a,
  0xdfab323c787b8512,  0x7b207573e68e590a,  0x8aa0bca2598c2022,  0x2e2bfbedc779fc3a,
  0x75bd331d3a88d272,  0xd1367452a47d0e6a,  0x20b6bd831b7f7742,  0x843dfacc858aab5a,
  0x04df34fae96b6a4f,  0xa05473b5779eb657,  0x51d4ba64c89ccf7f,  0xf55ffd2b56691367,
  0xaec935dbab983d2f,  0xa427294356de137,  0xfbc2bb458a6f981f,  0x5f49fc0a149a4407,
  0x4df336b86d90c48f,  0xe97871f7f3651897,  0x18f8b8264c6761bf,  0xbc73ff69d292bda7,
  0xe7e537992f6393ef,  0x436e70d6b1964ff7,  0xb2eeb9070e9436df,  0x1665fe489061eac7,
  0xaf37386bd64ba9f5,  0xbbc7f2448be75ed,  0xfa3cb6f5f7bc0cc5,  0x5eb7f1ba6949d0dd,
  0x0521394a94b8fe95,  0xa1aa7e050a4d228d,  0x502ab7d4b54f5ba5,  0xf4a1f09b2bba87bd,
  0xe61b3a2952b00735,  0x42907d66cc45db2d,  0xb310b4b77347a205,  0x179bf3f8edb27e1d,
  0x4c0d3b0810435055,  0xe8867c478eb68c4d,  0x1906b59631b4f565,  0xbd8df2d9af41297d,
  0x3d6f3cefc3a0e868,  0x99e47ba05d553470,  0x6864b271e2574d58,  0xcceff53e7ca29140,
  0x97793dce8153bf08,  0x33f27a811fa66310,  0xc272b350a0a41a38,  0x66f9f41f3e51c620,
  0x74433ead475b46a8,  0xd0c879e2d9ae9ab0,  0x2148b03366ace398,  0x85c3f77cf8593f80,
  0xde553f8c05a811c8,  0x7ade78c39b5dcdd0,  0x8b5eb112245fb4f8,  0x2fd5f65dbaaa68e0,
  },{
  0x0000000000000000,  0xf97d86d98a327728,  0xeffa11af0964ee50,  0x1687977683569978,
  0xc3e9224312c8c1a0,  0x3a94a49a98fab688,  0x2c1333ec1bac2ff0,  0xd56eb535919e58d8,
  0x9bcf4486248d9f5d,  0x62b2c25faebfe875,  0x743555292de9710d,  0x8d48d3f0a7db0625,
  0x582666c536455efd,  0xa15be01cbc7729d5,  0xb7dc776a3f21b0ad,  0x4ea1f1b3b513c785,
  0x2b838811480723ba,  0xd2fe0ec8c2355492,  0xc47999be4163cdea,  0x3d041f67cb51bac2,
  0xe86aaa525acfe21a,  0x11172c8bd0fd9532,  0x790bbfd53ab0c4a,  0xfeed3d24d9997b62,
  0xb04ccc976c8abce7,  0x49314a4ee6b8cbcf,  0x5fb6dd3865ee52b7,  0xa6cb5be1efdc259f,
  0x73a5eed47e427d47,  0x8ad8680df4700a6f,  0x9c5fff7b77269317,  0x652279a2fd14e43f,
  0x561b0d22900e4669,  0xaf668bfb1a3c3141,  0xb9e11c8d996aa839,  0x409c9a541358df11,
  0x95f22f6182c687c9,  0x6c8fa9b808f4f0e1,  0x7a083ece8ba26999,  0x8375b81701901eb1,
  0xcdd449a4b483d934,  0x34a9cf7d3eb1ae1c,  0x222e580bbde73764,  0xdb53ded237d5404c,
  0x0e3d6be7a64b1894,  0xf740ed3e2c796fbc,  0xe1c77a48af2ff6c4,  0x18bafc91251d81ec,
  0x7d988533d80965d3,  0x84e503ea523b12fb,  0x9262949cd16d8b83,  0x6b1f12455b5ffcab,
  0xbe71a770cac1a473,  0x470c21a940f3d35b,  0x518bb6dfc3a54a23,  0xa8f6300649973d0b,
  0xe657c1b5fc84fa8e,  0x1f2a476c76b68da6,  0x9add01af5e014de,  0xf0d056c37fd263f6,
  0x25bee3f6ee4c3b2e,  0xdcc3652f647e4c06,  0xca44f259e728d57e,  0x333974806d1aa256,
  0xac361a443d1c8cd2,  0x554b9c9db72efbfa,  0x43cc0beb34786282,  0xbab18d32be4a15aa,
  0x6fdf38072fd44d72,  0x96a2bedea5e63a5a,  0x802529a826b0a322,  0x7958af71ac82d40a,
  0x37f95ec21991138f,  0xce84d81b93a364a7,  0xd8034f6d10f5fddf,  0x217ec9b49ac78af7,
  0xf4107c810b59d22f,  0xd6dfa58816ba507,  0x1bea6d2e023d3c7f,  0xe297ebf7880f4b57,
  0x87b59255751baf68,  0x7ec8148cff29d840,  0x684f83fa7c7f4138,  0x91320523f64d3610,
  0x445cb01667d36ec8,  0xbd2136cfede119e0,  0xaba6a1b96eb78098,  0x52db2760e485f7b0,
  0x1c7ad6d351963035,  0xe507500adba4471d,  0xf380c77c58f2de65,  0xafd41a5d2c0a94d,
  0xdf93f490435ef195,  0x26ee7249c96c86bd,  0x3069e53f4a3a1fc5,  0xc91463e6c00868ed,
  0xfa2d1766ad12cabb,  0x35091bf2720bd93,  0x15d706c9a47624eb,  0xecaa80102e4453c3,
  0x39c43525bfda0b1b,  0xc0b9b3fc35e87c33,  0xd63e248ab6bee54b,  0x2f43a2533c8c9263,
  0x61e253e0899f55e6,  0x989fd53903ad22ce,  0x8e18424f80fbbbb6,  0x7765c4960ac9cc9e,
  0xa20b71a39b579446,  0x5b76f77a1165e36e,  0x4df1600c92337a16,  0xb48ce6d518010d3e,
  0xd1ae9f77e515e901,  0x28d319ae6f279e29,  0x3e548ed8ec710751,  0xc729080166437079,
  0x1247bd34f7dd28a1,  0xeb3a3bed7def5f89,  0xfdbdac9bfeb9c6f1,  0x4c02a42748bb1d9,
  0x4a61dbf1c198765c,  0xb31c5d284baa0174,  0xa59bca5ec8fc980c,  0x5ce64c8742ceef24,
  0x8988f9b2d350b7fc,  0x70f57f6b5962c0d4,  0x6672e81dda3459ac,  0x9f0f6ec450062e84,
  0x456c34887a3805b9,  0xbc11b251f00a7291,  0xaa962527735cebe9,  0x53eba3fef96e9cc1,
  0x868516cb68f0c419,  0x7ff89012e2c2b331,  0x697f076461942a49,  0x900281bdeba65d61,
  0xdea3700e5eb59ae4,  0x27def6d7d487edcc,  0x315961a157d174b4,  0xc824e778dde3039c,
  0x1d4a524d4c7d5b44,  0xe437d494c64f2c6c,  0xf2b043e24519b514,  0xbcdc53bcf2bc23c,
  0x6eefbc99323f2603,  0x97923a40b80d512b,  0x8115ad363b5bc853,  0x78682befb169bf7b,
  0xad069eda20f7e7a3,  0x547b1803aac5908b,  0x42fc8f75299309f3,  0xbb8109aca3a17edb,
  0xf520f81f16b2b95e,  0xc5d7ec69c80ce76,  0x1adae9b01fd6570e,  0xe3a76f6995e42026,
  0x36c9da5c047a78fe,  0xcfb45c858e480fd6,  0xd933cbf30d1e96ae,  0x204e4d2a872ce186,
  0x137739aaea3643d0,  0xea0abf73600434f8,  0xfc8d2805e352ad80,  0x5f0aedc6960daa8,
  0xd09e1be9f8fe8270,  0x29e39d3072ccf558,  0x3f640a46f19a6c20,  0xc6198c9f7ba81b08,
  0x88b87d2ccebbdc8d,  0x71c5fbf54489aba5,  0x67426c83c7df32dd,  0x9e3fea5a4ded45f5,
  0x4b515f6fdc731d2d,  0xb22cd9b656416a05,  0xa4ab4ec0d517f37d,  0x5dd6c8195f258455,
  0x38f4b1bba231606a,  0xc189376228031742,  0xd70ea014ab558e3a,  0x2e7326cd2167f912,
  0xfb1d93f8b0f9a1ca,  0x26015213acbd6e2,  0x14e78257b99d4f9a,  0xed9a048e33af38b2,
  0xa33bf53d86bcff37,  0x5a4673e40c8e881f,  0x4cc1e4928fd81167,  0xb5bc624b05ea664f,
  0x60d2d77e94743e97,  0x99af51a71e4649bf,  0x8f28c6d19d10d0c7,  0x765540081722a7ef,
  0xe95a2ecc4724896b,  0x1027a815cd16fe43,  0x6a03f634e40673b,  0xffddb9bac4721013,
  0x2ab30c8f55ec48cb,  0xd3ce8a56dfde3fe3,  0xc5491d205c88a69b,  0x3c349bf9d6bad1b3,
  0x72956a4a63a91636,  0x8be8ec93e99b611e,  0x9d6f7be56acdf866,  0x6412fd3ce0ff8f4e,
  0xb17c48097161d796,  0x4801ced0fb53a0be,  0x5e8659a6780539c6,  0xa7fbdf7ff2374eee,
  0xc2d9a6dd0f23aad1,  0x3ba420048511ddf9,  0x2d23b77206474481,  0xd45e31ab8c7533a9,
  0x0130849e1deb6b71,  0xf84d024797d91c59,  0xeeca9531148f8521,  0x17b713e89ebdf209,
  0x5916e25b2bae358c,  0xa06b6482a19c42a4,  0xb6ecf3f422cadbdc,  0x4f91752da8f8acf4,
  0x9affc0183966f42c,  0x638246c1b3548304,  0x7505d1b730021a7c,  0x8c78576eba306d54,
  0xbf4123eed72acf02,  0x463ca5375d18b82a,  0x50bb3241de4e2152,  0xa9c6b498547c567a,
  0x7ca801adc5e20ea2,  0x85d587744fd0798a,  0x93521002cc86e0f2,  0x6a2f96db46b497da,
  0x248e6768f3a7505f,  0xddf3e1b179952777,  0xcb7476c7fac3be0f,  0x3209f01e70f1c927,
  0xe767452be16f91ff,  0x1e1ac3f26b5de6d7,  0x89d5484e80b7faf,  0xf1e0d25d62390887,
  0x94c2abff9f2decb8,  0x6dbf2d26151f9b90,  0x7b38ba50964902e8,  0x82453c891c7b75c0,
  0x572b89bc8de52d18,  0xae560f6507d75a30,  0xb8d198138481c348,  0x41ac1eca0eb3b460,
  0x0f0def79bba073e5,  0xf67069a0319204cd,  0xe0f7fed6b2c49db5,  0x198a780f38f6ea9d,
  0xcce4cd3aa968b245,  0x35994be3235ac56d,  0x231edc95a00c5c15,  0xda635a4c2a3e2b3d,
  },{
  0x0000000000000000,  0x5b068c651810a89e,  0xb60c05ca30204d21,  0xed0a89af2830e5bf,
  0x71180a8960409a42,  0x2a1e86ec785032dc,  0xc7140f435060d763,  0x9c12832648707ffd,
  0xe230140fc0802984,  0xb936986ad890811a,  0x543c11c5f0a064a5,  0xf3a9da0e8b0cc3b,
  0x93281e86a0c0b3c6,  0xc82e92e3b8d01b58,  0x25241b4c90e0fee7,  0x7e22972988f05679,
  0xd960281e9d1d5215,  0x8266a47b850dfa8b,  0x6f6c2dd4ad3d1f34,  0x346aa1b1b52db7aa,
  0xa8782297fd5dc857,  0xf37eaef2e54d60c9,  0x1e74275dcd7d8576,  0x4572ab38d56d2de8,
  0x3b503c115d9d7b91,  0x6056b074458dd30f,  0x8d5c39db6dbd36b0,  0xd65ab5be75ad9e2e,
  0x4a4836983ddde1d3,  0x114ebafd25cd494d,  0xfc4433520dfdacf2,  0xa742bf3715ed046c,
  0xafc0503c273aa42a,  0xf4c6dc593f2a0cb4,  0x19cc55f6171ae90b,  0x42cad9930f0a4195,
  0xded85ab5477a3e68,  0x85ded6d05f6a96f6,  0x68d45f7f775a7349,  0x33d2d31a6f4adbd7,
  0x4df04433e7ba8dae,  0x16f6c856ffaa2530,  0xfbfc41f9d79ac08f,  0xa0facd9ccf8a6811,
  0x3ce84eba87fa17ec,  0x67eec2df9feabf72,  0x8ae44b70b7da5acd,  0xd1e2c715afcaf253,
  0x76a07822ba27f63f,  0x2da6f447a2375ea1,  0xc0ac7de88a07bb1e,  0x9baaf18d92171380,
  0x07b872abda676c7d,  0x5cbefecec277c4e3,  0xb1b47761ea47215c,  0xeab2fb04f25789c2,
  0x94906c2d7aa7dfbb,  0xcf96e04862b77725,  0x229c69e74a87929a,  0x799ae58252973a04,
  0xe58866a41ae745f9,  0xbe8eeac102f7ed67,  0x5384636e2ac708d8,  0x882ef0b32d7a046,
  0x439da0784e745554,  0x189b2c1d5664fdca,  0xf591a5b27e541875,  0xae9729d76644b0eb,
  0x3285aaf12e34cf16,  0x6983269436246788,  0x8489af3b1e148237,  0xdf8f235e06042aa9,
  0xa1adb4778ef47cd0,  0xfaab381296e4d44e,  0x17a1b1bdbed431f1,  0x4ca73dd8a6c4996f,
  0xd0b5befeeeb4e692,  0x8bb3329bf6a44e0c,  0x66b9bb34de94abb3,  0x3dbf3751c684032d,
  0x9afd8866d3690741,  0xc1fb0403cb79afdf,  0x2cf18dace3494a60,  0x77f701c9fb59e2fe,
  0xebe582efb3299d03,  0xb0e30e8aab39359d,  0x5de987258309d022,  0x6ef0b409b1978bc,
  0x78cd9c6913e92ec5,  0x23cb100c0bf9865b,  0xcec199a323c963e4,  0x95c715c63bd9cb7a,
  0x09d596e073a9b487,  0x52d31a856bb91c19,  0xbfd9932a4389f9a6,  0xe4df1f4f5b995138,
  0xec5df044694ef17e,  0xb75b7c21715e59e0,  0x5a51f58e596ebc5f,  0x15779eb417e14c1,
  0x9d45facd090e6b3c,  0xc64376a8111ec3a2,  0x2b49ff07392e261d,  0x704f7362213e8e83,
  0x0e6de44ba9ced8fa,  0x556b682eb1de7064,  0xb861e18199ee95db,  0xe3676de481fe3d45,
  0x7f75eec2c98e42b8,  0x247362a7d19eea26,  0xc979eb08f9ae0f99,  0x927f676de1bea707,
  0x353dd85af453a36b,  0x6e3b543fec430bf5,  0x8331dd90c473ee4a,  0xd83751f5dc6346d4,
  0x4425d2d394133929,  0x1f235eb68c0391b7,  0xf229d719a4337408,  0xa92f5b7cbc23dc96,
  0xd70dcc5534d38aef,  0x8c0b40302cc32271,  0x6101c99f04f3c7ce,  0x3a0745fa1ce36f50,
  0xa615c6dc549310ad,  0xfd134ab94c83b833,  0x1019c31664b35d8c,  0x4b1f4f737ca3f512,
  0x86275df09ce8aaa8,  0xdd21d19584f80236,  0x302b583aacc8e789,  0x6b2dd45fb4d84f17,
  0xf73f5779fca830ea,  0xac39db1ce4b89874,  0x413352b3cc887dcb,  0x1a35ded6d498d555,
  0x641749ff5c68832c,  0x3f11c59a44782bb2,  0xd21b4c356c48ce0d,  0x891dc05074586693,
  0x150f43763c28196e,  0x4e09cf132438b1f0,  0xa30346bc0c08544f,  0xf805cad91418fcd1,
  0x5f4775ee01f5f8bd,  0x441f98b19e55023,  0xe94b702431d5b59c,  0xb24dfc4129c51d02,
  0x2e5f7f6761b562ff,  0x7559f30279a5ca61,  0x98537aad51952fde,  0xc355f6c849858740,
  0xbd7761e1c175d139,  0xe671ed84d96579a7,  0xb7b642bf1559c18,  0x507de84ee9453486,
  0xcc6f6b68a1354b7b,  0x9769e70db925e3e5,  0x7a636ea29115065a,  0x2165e2c78905aec4,
  0x29e70dccbbd20e82,  0x72e181a9a3c2a61c,  0x9feb08068bf243a3,  0xc4ed846393e2eb3d,
  0x58ff0745db9294c0,  0x3f98b20c3823c5e,  0xeef3028febb2d9e1,  0xb5f58eeaf3a2717f,
  0xcbd719c37b522706,  0x90d195a663428f98,  0x7ddb1c094b726a27,  0x26dd906c5362c2b9,
  0xbacf134a1b12bd44,  0xe1c99f2f030215da,  0xcc316802b32f065,  0x57c59ae5332258fb,
  0xf08725d226cf5c97,  0xab81a9b73edff409,  0x468b201816ef11b6,  0x1d8dac7d0effb928,
  0x819f2f5b468fc6d5,  0xda99a33e5e9f6e4b,  0x37932a9176af8bf4,  0x6c95a6f46ebf236a,
  0x12b731dde64f7513,  0x49b1bdb8fe5fdd8d,  0xa4bb3417d66f3832,  0xffbdb872ce7f90ac,
  0x63af3b54860fef51,  0x38a9b7319e1f47cf,  0xd5a33e9eb62fa270,  0x8ea5b2fbae3f0aee,
  0xc5bafd88d29cfffc,  0x9ebc71edca8c5762,  0x73b6f842e2bcb2dd,  0x28b07427faac1a43,
  0xb4a2f701b2dc65be,  0xefa47b64aacccd20,  0x2aef2cb82fc289f,  0x59a87eae9aec8001,
  0x278ae987121cd678,  0x7c8c65e20a0c7ee6,  0x9186ec4d223c9b59,  0xca8060283a2c33c7,
  0x5692e30e725c4c3a,  0xd946f6b6a4ce4a4,  0xe09ee6c4427c011b,  0xbb986aa15a6ca985,
  0x1cdad5964f81ade9,  0x47dc59f357910577,  0xaad6d05c7fa1e0c8,  0xf1d05c3967b14856,
  0x6dc2df1f2fc137ab,  0x36c4537a37d19f35,  0xdbcedad51fe17a8a,  0x80c856b007f1d214,
  0xfeeac1998f01846d,  0xa5ec4dfc97112cf3,  0x48e6c453bf21c94c,  0x13e04836a73161d2,
  0x8ff2cb10ef411e2f,  0xd4f44775f751b6b1,  0x39fecedadf61530e,  0x62f842bfc771fb90,
  0x6a7aadb4f5a65bd6,  0x317c21d1edb6f348,  0xdc76a87ec58616f7,  0x8770241bdd96be69,
  0x1b62a73d95e6c194,  0x40642b588df6690a,  0xad6ea2f7a5c68cb5,  0xf6682e92bdd6242b,
  0x884ab9bb35267252,  0xd34c35de2d36dacc,  0x3e46bc7105063f73,  0x654030141d1697ed,
  0xf952b3325566e810,  0xa2543f574d76408e,  0x4f5eb6f86546a531,  0x14583a9d7d560daf,
  0xb31a85aa68bb09c3,  0xe81c09cf70aba15d,  0x5168060589b44e2,  0x5e100c05408bec7c,
  0xc2028f2308fb9381,  0x9904034610eb3b1f,  0x740e8ae938dbdea0,  0x2f08068c20cb763e,
  0x512a91a5a83b2047,  0xa2c1dc0b02b88d9,  0xe726946f981b6d66,  0xbc20180a800bc5f8,
  0x20329b2cc87bba05,  0x7b341749d06b129b,  0x963e9ee6f85bf724,  0xcd381283e04b5fba,
  },{
  0x0000000000000000,  0x321658cba93c138,  0x642ca05693b9f70,  0x563af89d3a85e48,
  0x0c84890ad27623e0,  0xfa5ec8668e5e2d8,  0xac6430fbb4dbc90,  0x9e7268301de7da8,
  0x18150f14b9ec46dd,  0x1b346a98037f87e5,  0x1e57c511d0d7d9ad,  0x1d76a09d6a441895,
  0x1491861e6b9a653d,  0x17b0e392d109a405,  0x12d34c1b02a1fa4d,  0x11f22997b8323b75,
  0x302a1e286fc58ca7,  0x330b7ba4d5564d9f,  0x3668d42d06fe13d7,  0x3549b1a1bc6dd2ef,
  0x3cae9722bdb3af47,  0x3f8ff2ae07206e7f,  0x3aec5d27d4883037,  0x39cd38ab6e1bf10f,
  0x283f113cd629ca7a,  0x2b1e74b06cba0b42,  0x2e7ddb39bf12550a,  0x2d5cbeb505819432,
  0x24bb9836045fe99a,  0x279afdbabecc28a2,  0x22f952336d6476ea,  0x21d837bfd7f7b7d2,
  0x60543c50de970553,  0x637559dc6404c46b,  0x6616f655b7ac9a23,  0x653793d90d3f5b1b,
  0x6cd0b55a0ce126b3,  0x6ff1d0d6b672e78b,  0x6a927f5f65dab9c3,  0x69b31ad3df4978fb,
  0x78413344677b438e,  0x7b6056c8dde882b6,  0x7e03f9410e40dcfe,  0x7d229ccdb4d31dc6,
  0x74c5ba4eb50d606e,  0x77e4dfc20f9ea156,  0x7287704bdc36ff1e,  0x71a615c766a53e26,
  0x507e2278b15289f4,  0x535f47f40bc148cc,  0x563ce87dd8691684,  0x551d8df162fad7bc,
  0x5cfaab726324aa14,  0x5fdbcefed9b76b2c,  0x5ab861770a1f3564,  0x599904fbb08cf45c,
  0x486b2d6c08becf29,  0x4b4a48e0b22d0e11,  0x4e29e76961855059,  0x4d0882e5db169161,
  0x44efa466dac8ecc9,  0x47cec1ea605b2df1,  0x42ad6e63b3f373b9,  0x418c0bef0960b281,
  0xc0a878a0a1330aa6,  0xc3891d2c1ba0cb9e,  0xc6eab2a5c80895d6,  0xc5cbd729729b54ee,
  0xcc2cf1aa73452946,  0xcf0d9426c9d6e87e,  0xca6e3baf1a7eb636,  0xc94f5e23a0ed770e,
  0xd8bd77b418df4c7b,  0xdb9c1238a24c8d43,  0xdeffbdb171e4d30b,  0xddded83dcb771233,
  0xd439febecaa96f9b,  0xd7189b32703aaea3,  0xd27b34bba392f0eb,  0xd15a5137190131d3,
  0xf0826688cef68601,  0xf3a3030474654739,  0xf6c0ac8da7cd1971,  0xf5e1c9011d5ed849,
  0xfc06ef821c80a5e1,  0xff278a0ea61364d9,  0xfa44258775bb3a91,  0xf965400bcf28fba9,
  0xe897699c771ac0dc,  0xebb60c10cd8901e4,  0xeed5a3991e215fac,  0xedf4c615a4b29e94,
  0xe413e096a56ce33c,  0xe732851a1fff2204,  0xe2512a93cc577c4c,  0xe1704f1f76c4bd74,
  0xa0fc44f07fa40ff5,  0xa3dd217cc537cecd,  0xa6be8ef5169f9085,  0xa59feb79ac0c51bd,
  0xac78cdfaadd22c15,  0xaf59a8761741ed2d,  0xaa3a07ffc4e9b365,  0xa91b62737e7a725d,
  0xb8e94be4c6484928,  0xbbc82e687cdb8810,  0xbeab81e1af73d658,  0xbd8ae46d15e01760,
  0xb46dc2ee143e6ac8,  0xb74ca762aeadabf0,  0xb22f08eb7d05f5b8,  0xb10e6d67c7963480,
  0x90d65ad810618352,  0x93f73f54aaf2426a,  0x969490dd795a1c22,  0x95b5f551c3c9dd1a,
  0x9c52d3d2c217a0b2,  0x9f73b65e7884618a,  0x9a1019d7ab2c3fc2,  0x99317c5b11bffefa,
  0x88c355cca98dc58f,  0x8be23040131e04b7,  0x8e819fc9c0b65aff,  0x8da0fa457a259bc7,
  0x8447dcc67bfbe66f,  0x8766b94ac1682757,  0x820516c312c0791f,  0x8124734fa853b827,
  0x9d4df05d5f661451,  0x9e6c95d1e5f5d569,  0x9b0f3a58365d8b21,  0x982e5fd48cce4a19,
  0x91c979578d1037b1,  0x92e81cdb3783f689,  0x978bb352e42ba8c1,  0x94aad6de5eb869f9,
  0x8558ff49e68a528c,  0x86799ac55c1993b4,  0x831a354c8fb1cdfc,  0x803b50c035220cc4,
  0x89dc764334fc716c,  0x8afd13cf8e6fb054,  0x8f9ebc465dc7ee1c,  0x8cbfd9cae7542f24,
  0xad67ee7530a398f6,  0xae468bf98a3059ce,  0xab25247059980786,  0xa80441fce30bc6be,
  0xa1e3677fe2d5bb16,  0xa2c202f358467a2e,  0xa7a1ad7a8bee2466,  0xa480c8f6317de55e,
  0xb572e161894fde2b,  0xb65384ed33dc1f13,  0xb3302b64e074415b,  0xb0114ee85ae78063,
  0xb9f6686b5b39fdcb,  0xbad70de7e1aa3cf3,  0xbfb4a26e320262bb,  0xbc95c7e28891a383,
  0xfd19cc0d81f11102,  0xfe38a9813b62d03a,  0xfb5b0608e8ca8e72,  0xf87a638452594f4a,
  0xf19d4507538732e2,  0xf2bc208be914f3da,  0xf7df8f023abcad92,  0xf4feea8e802f6caa,
  0xe50cc319381d57df,  0xe62da695828e96e7,  0xe34e091c5126c8af,  0xe06f6c90ebb50997,
  0xe9884a13ea6b743f,  0xeaa92f9f50f8b507,  0xefca80168350eb4f,  0xecebe59a39c32a77,
  0xcd33d225ee349da5,  0xce12b7a954a75c9d,  0xcb711820870f02d5,  0xc8507dac3d9cc3ed,
  0xc1b75b2f3c42be45,  0xc2963ea386d17f7d,  0xc7f5912a55792135,  0xc4d4f4a6efeae00d,
  0xd526dd3157d8db78,  0xd607b8bded4b1a40,  0xd36417343ee34408,  0xd04572b884708530,
  0xd9a2543b85aef898,  0xda8331b73f3d39a0,  0xdfe09e3eec9567e8,  0xdcc1fbb25606a6d0,
  0x5de588fdfe551ef7,  0x5ec4ed7144c6dfcf,  0x5ba742f8976e8187,  0x588627742dfd40bf,
  0x516101f72c233d17,  0x5240647b96b0fc2f,  0x5723cbf24518a267,  0x5402ae7eff8b635f,
  0x45f087e947b9582a,  0x46d1e265fd2a9912,  0x43b24dec2e82c75a,  0x4093286094110662,
  0x49740ee395cf7bca,  0x4a556b6f2f5cbaf2,  0x4f36c4e6fcf4e4ba,  0x4c17a16a46672582,
  0x6dcf96d591909250,  0x6eeef3592b035368,  0x6b8d5cd0f8ab0d20,  0x68ac395c4238cc18,
  0x614b1fdf43e6b1b0,  0x626a7a53f9757088,  0x6709d5da2add2ec0,  0x6428b056904eeff8,
  0x75da99c1287cd48d,  0x76fbfc4d92ef15b5,  0x739853c441474bfd,  0x70b93648fbd48ac5,
  0x795e10cbfa0af76d,  0x7a7f754740993655,  0x7f1cdace9331681d,  0x7c3dbf4229a2a925,
  0x3db1b4ad20c21ba4,  0x3e90d1219a51da9c,  0x3bf37ea849f984d4,  0x38d21b24f36a45ec,
  0x31353da7f2b43844,  0x3214582b4827f97c,  0x3777f7a29b8fa734,  0x3456922e211c660c,
  0x25a4bbb9992e5d79,  0x2685de3523bd9c41,  0x23e671bcf015c209,  0x20c714304a860331,
  0x292032b34b587e99,  0x2a01573ff1cbbfa1,  0x2f62f8b62263e1e9,  0x2c439d3a98f020d1,
  0x0d9baa854f079703,  0xebacf09f594563b,  0xbd96080263c0873,  0x8f8050c9cafc94b,
  0x011f238f9d71b4e3,  0x23e460327e275db,  0x75de98af44a2b93,  0x47c8c064ed9eaab,
  0x158ea591f6ebd1de,  0x16afc01d4c7810e6,  0x13cc6f949fd04eae,  0x10ed0a1825438f96,
  0x190a2c9b249df23e,  0x1a2b49179e0e3306,  0x1f48e69e4da66d4e,  0x1c698312f735ac76,
  },{
  0x0000000000000000,  0xaccc9ca9328a8950,  0x4585254f64090fa0,  0xe949b9e6568386f0,
  0x8a174a9ec8121e5d,  0x26dbd637fa98970d,  0xcf926fd1ac1b11fd,  0x635ef3789e9198ad,
  0x092e94218d243cba,  0xa5e20888bfaeb5ea,  0x4cabb16ee92d331a,  0xe0672dc7dba7ba4a,
  0x8339debf453622e7,  0x2ff5421677bcabb7,  0xc6bcfbf0213f2d47,  0x6a70675913b5a417,
  0x125c354207487869,  0xbe90a9eb35c2f139,  0x57d9100d634177c9,  0xfb158ca451cbfe99,
  0x984b7fdccf5a6634,  0x3487e375fdd0ef64,  0xddce5a93ab536994,  0x7102c63a99d9e0c4,
  0x1b72a1638a6c44d3,  0xb7be3dcab8e6cd83,  0x5ef7842cee654b73,  0xf23b1885dcefc223,
  0x9165ebfd427e5a8e,  0x3da9775470f4d3de,  0xd4e0ceb22677552e,  0x782c521b14fddc7e,
  0x24b86a840e90f0d2,  0x8874f62d3c1a7982,  0x613d4fcb6a99ff72,  0xcdf1d36258137622,
  0xaeaf201ac682ee8f,  0x263bcb3f40867df,  0xeb2a0555a28be12f,  0x47e699fc9001687f,
  0x2d96fea583b4cc68,  0x815a620cb13e4538,  0x6813dbeae7bdc3c8,  0xc4df4743d5374a98,
  0xa781b43b4ba6d235,  0xb4d2892792c5b65,  0xe20491742fafdd95,  0x4ec80ddd1d2554c5,
  0x36e45fc609d888bb,  0x9a28c36f3b5201eb,  0x73617a896dd1871b,  0xdfade6205f5b0e4b,
  0xbcf31558c1ca96e6,  0x103f89f1f3401fb6,  0xf9763017a5c39946,  0x55baacbe97491016,
  0x3fcacbe784fcb401,  0x9306574eb6763d51,  0x7a4feea8e0f5bba1,  0xd6837201d27f32f1,
  0xb5dd81794ceeaa5c,  0x19111dd07e64230c,  0xf058a43628e7a5fc,  0x5c94389f1a6d2cac,
  0x486dd4151c3dfdb9,  0xe4a148bc2eb774e9,  0xde8f15a7834f219,  0xa1246df34abe7b49,
  0xc27a9e8bd42fe3e4,  0x6eb60222e6a56ab4,  0x87ffbbc4b026ec44,  0x2b33276d82ac6514,
  0x414340349119c103,  0xed8fdc9da3934853,  0x4c6657bf510cea3,  0xa80af9d2c79a47f3,
  0xcb540aaa590bdf5e,  0x679896036b81560e,  0x8ed12fe53d02d0fe,  0x221db34c0f8859ae,
  0x5a31e1571b7585d0,  0xf6fd7dfe29ff0c80,  0x1fb4c4187f7c8a70,  0xb37858b14df60320,
  0xd026abc9d3679b8d,  0x7cea3760e1ed12dd,  0x95a38e86b76e942d,  0x396f122f85e41d7d,
  0x531f75769651b96a,  0xffd3e9dfa4db303a,  0x169a5039f258b6ca,  0xba56cc90c0d23f9a,
  0xd9083fe85e43a737,  0x75c4a3416cc92e67,  0x9c8d1aa73a4aa897,  0x3041860e08c021c7,
  0x6cd5be9112ad0d6b,  0xc01922382027843b,  0x29509bde76a402cb,  0x859c0777442e8b9b,
  0xe6c2f40fdabf1336,  0x4a0e68a6e8359a66,  0xa347d140beb61c96,  0xf8b4de98c3c95c6,
  0x65fb2ab09f8931d1,  0xc937b619ad03b881,  0x207e0ffffb803e71,  0x8cb29356c90ab721,
  0xefec602e579b2f8c,  0x4320fc876511a6dc,  0xaa6945613392202c,  0x6a5d9c80118a97c,
  0x7e898bd315e57502,  0xd245177a276ffc52,  0x3b0cae9c71ec7aa2,  0x97c032354366f3f2,
  0xf49ec14dddf76b5f,  0x58525de4ef7de20f,  0xb11be402b9fe64ff,  0x1dd778ab8b74edaf,
  0x77a71ff298c149b8,  0xdb6b835baa4bc0e8,  0x32223abdfcc84618,  0x9eeea614ce42cf48,
  0xfdb0556c50d357e5,  0x517cc9c56259deb5,  0xb835702334da5845,  0x14f9ec8a0650d115,
  0x90dab52a387ae76f,  0x3c1629830af06e3f,  0xd55f90655c73e8cf,  0x79930ccc6ef9619f,
  0x1acdffb4f068f932,  0xb601631dc2e27062,  0x5f48dafb9461f692,  0xf3844652a6eb7fc2,
  0x99f4210bb55edbd5,  0x3538bda287d45285,  0xdc710444d157d475,  0x70bd98ede3dd5d25,
  0x13e36b957d4cc588,  0xbf2ff73c4fc64cd8,  0x56664eda1945ca28,  0xfaaad2732bcf4378,
  0x828680683f329f06,  0x2e4a1cc10db81656,  0xc703a5275b3b90a6,  0x6bcf398e69b119f6,
  0x0891caf6f720815b,  0xa45d565fc5aa080b,  0x4d14efb993298efb,  0xe1d87310a1a307ab,
  0x8ba81449b216a3bc,  0x276488e0809c2aec,  0xce2d3106d61fac1c,  0x62e1adafe495254c,
  0x01bf5ed77a04bde1,  0xad73c27e488e34b1,  0x443a7b981e0db241,  0xe8f6e7312c873b11,
  0xb462dfae36ea17bd,  0x18ae430704609eed,  0xf1e7fae152e3181d,  0x5d2b66486069914d,
  0x3e759530fef809e0,  0x92b90999cc7280b0,  0x7bf0b07f9af10640,  0xd73c2cd6a87b8f10,
  0xbd4c4b8fbbce2b07,  0x1180d7268944a257,  0xf8c96ec0dfc724a7,  0x5405f269ed4dadf7,
  0x375b011173dc355a,  0x9b979db84156bc0a,  0x72de245e17d53afa,  0xde12b8f7255fb3aa,
  0xa63eeaec31a26fd4,  0xaf276450328e684,  0xe3bbcfa355ab6074,  0x4f77530a6721e924,
  0x2c29a072f9b07189,  0x80e53cdbcb3af8d9,  0x69ac853d9db97e29,  0xc5601994af33f779,
  0xaf107ecdbc86536e,  0x3dce2648e0cda3e,  0xea955b82d88f5cce,  0x4659c72bea05d59e,
  0x2507345374944d33,  0x89cba8fa461ec463,  0x6082111c109d4293,  0xcc4e8db52217cbc3,
  0xd8b7613f24471ad6,  0x747bfd9616cd9386,  0x9d324470404e1576,  0x31fed8d972c49c26,
  0x52a02ba1ec55048b,  0xfe6cb708dedf8ddb,  0x17250eee885c0b2b,  0xbbe99247bad6827b,
  0xd199f51ea963266c,  0x7d5569b79be9af3c,  0x941cd051cd6a29cc,  0x38d04cf8ffe0a09c,
  0x5b8ebf8061713831,  0xf742232953fbb161,  0x1e0b9acf05783791,  0xb2c7066637f2bec1,
  0xcaeb547d230f62bf,  0x6627c8d41185ebef,  0x8f6e713247066d1f,  0x23a2ed9b758ce44f,
  0x40fc1ee3eb1d7ce2,  0xec30824ad997f5b2,  0x5793bac8f147342,  0xa9b5a705bd9efa12,
  0xc3c5c05cae2b5e05,  0x6f095cf59ca1d755,  0x8640e513ca2251a5,  0x2a8c79baf8a8d8f5,
  0x49d28ac266394058,  0xe51e166b54b3c908,  0xc57af8d02304ff8,  0xa09b332430bac6a8,
  0xfc0f0bbb2ad7ea04,  0x50c39712185d6354,  0xb98a2ef44edee5a4,  0x1546b25d7c546cf4,
  0x76184125e2c5f459,  0xdad4dd8cd04f7d09,  0x339d646a86ccfbf9,  0x9f51f8c3b44672a9,
  0xf5219f9aa7f3d6be,  0x59ed033395795fee,  0xb0a4bad5c3fad91e,  0x1c68267cf170504e,
  0x7f36d5046fe1c8e3,  0xd3fa49ad5d6b41b3,  0x3ab3f04b0be8c743,  0x967f6ce239624e13,
  0xee533ef92d9f926d,  0x429fa2501f151b3d,  0xabd61bb649969dcd,  0x71a871f7b1c149d,
  0x64447467e58d8c30,  0xc888e8ced7070560,  0x21c1512881848390,  0x8d0dcd81b30e0ac0,
  0xe77daad8a0bbaed7,  0x4bb1367192312787,  0xa2f88f97c4b2a177,  0xe34133ef6382827,
  0x6d6ae04668a9b08a,  0xc1a67cef5a2339da,  0x28efc5090ca0bf2a,  0x842359a03e2a367a,
  },{
  0x0000000000000000,  0x46b60f011a83988e,  0x8c711e02341b2d01,  0xcac711032e98b58f,
  0x05e23c0468365a02,  0x4354330572b5c28c,  0x899322065c2d7703,  0xcf252d0746aeef8d,
  0x0ad97808d06cb404,  0x4c6f7709caef2c8a,  0x86a8660ae4779905,  0xc01e690bfef4018b,
  0x0f3b440cb85aee06,  0x498d4b0da2d97688,  0x834a5a0e8c41c307,  0xc5fc550f96c25b89,
  0x14aff010bdd87508,  0x5219ff11a75bed86,  0x98deee1289c35809,  0xde68e1139340c087,
  0x114dcc14d5ee2f0a,  0x57fbc315cf6db784,  0x9d3cd216e1f5020b,  0xdb8add17fb769a85,
  0x1e7688186db4c10c,  0x58c0871977375982,  0x9207961a59afec0d,  0xd4b1991b432c7483,
  0x1b94b41c05829b0e,  0x5d22bb1d1f010380,  0x97e5aa1e3199b60f,  0xd153a51f2b1a2e81,
  0x2843fd2067adea10,  0x6ef5f2217d2e729e,  0xa432e32253b6c711,  0xe284ec2349355f9f,
  0x2da1c1240f9bb012,  0x6b17ce251518289c,  0xa1d0df263b809d13,  0xe766d0272103059d,
  0x229a8528b7c15e14,  0x642c8a29ad42c69a,  0xaeeb9b2a83da7315,  0xe85d942b9959eb9b,
  0x2778b92cdff70416,  0x61ceb62dc5749c98,  0xab09a72eebec2917,  0xedbfa82ff16fb199,
  0x3cec0d30da759f18,  0x7a5a0231c0f60796,  0xb09d1332ee6eb219,  0xf62b1c33f4ed2a97,
  0x390e3134b243c51a,  0x7fb83e35a8c05d94,  0xb57f2f368658e81b,  0xf3c920379cdb7095,
  0x363575380a192b1c,  0x70837a39109ab392,  0xba446b3a3e02061d,  0xfcf2643b24819e93,
  0x33d7493c622f711e,  0x7561463d78ace990,  0xbfa6573e56345c1f,  0xf910583f4cb7c491,
  0x5086e740ce47c920,  0x1630e841d4c451ae,  0xdcf7f942fa5ce421,  0x9a41f643e0df7caf,
  0x5564db44a6719322,  0x13d2d445bcf20bac,  0xd915c546926abe23,  0x9fa3ca4788e926ad,
  0x5a5f9f481e2b7d24,  0x1ce9904904a8e5aa,  0xd62e814a2a305025,  0x90988e4b30b3c8ab,
  0x5fbda34c761d2726,  0x190bac4d6c9ebfa8,  0xd3ccbd4e42060a27,  0x957ab24f588592a9,
  0x44291750739fbc28,  0x29f1851691c24a6,  0xc858095247849129,  0x8eee06535d0709a7,
  0x41cb2b541ba9e62a,  0x77d2455012a7ea4,  0xcdba35562fb2cb2b,  0x8b0c3a57353153a5,
  0x4ef06f58a3f3082c,  0x8466059b97090a2,  0xc281715a97e8252d,  0x84377e5b8d6bbda3,
  0x4b12535ccbc5522e,  0xda45c5dd146caa0,  0xc7634d5effde7f2f,  0x81d5425fe55de7a1,
  0x78c51a60a9ea2330,  0x3e731561b369bbbe,  0xf4b404629df10e31,  0xb2020b63877296bf,
  0x7d272664c1dc7932,  0x3b912965db5fe1bc,  0xf1563866f5c75433,  0xb7e03767ef44ccbd,
  0x721c626879869734,  0x34aa6d6963050fba,  0xfe6d7c6a4d9dba35,  0xb8db736b571e22bb,
  0x77fe5e6c11b0cd36,  0x3148516d0b3355b8,  0xfb8f406e25abe037,  0xbd394f6f3f2878b9,
  0x6c6aea7014325638,  0x2adce5710eb1ceb6,  0xe01bf47220297b39,  0xa6adfb733aaae3b7,
  0x6988d6747c040c3a,  0x2f3ed975668794b4,  0xe5f9c876481f213b,  0xa34fc777529cb9b5,
  0x66b39278c45ee23c,  0x20059d79dedd7ab2,  0xeac28c7af045cf3d,  0xac74837beac657b3,
  0x6351ae7cac68b83e,  0x25e7a17db6eb20b0,  0xef20b07e9873953f,  0xa996bf7f82f00db1,
  0xa011d380818e8f40,  0xe6a7dc819b0d17ce,  0x2c60cd82b595a241,  0x6ad6c283af163acf,
  0xa5f3ef84e9b8d542,  0xe345e085f33b4dcc,  0x2982f186dda3f843,  0x6f34fe87c72060cd,
  0xaac8ab8851e23b44,  0xec7ea4894b61a3ca,  0x26b9b58a65f91645,  0x600fba8b7f7a8ecb,
  0xaf2a978c39d46146,  0xe99c988d2357f9c8,  0x235b898e0dcf4c47,  0x65ed868f174cd4c9,
  0xb4be23903c56fa48,  0xf2082c9126d562c6,  0x38cf3d92084dd749,  0x7e79329312ce4fc7,
  0xb15c1f945460a04a,  0xf7ea10954ee338c4,  0x3d2d0196607b8d4b,  0x7b9b0e977af815c5,
  0xbe675b98ec3a4e4c,  0xf8d15499f6b9d6c2,  0x3216459ad821634d,  0x74a04a9bc2a2fbc3,
  0xbb85679c840c144e,  0xfd33689d9e8f8cc0,  0x37f4799eb017394f,  0x7142769faa94a1c1,
  0x88522ea0e6236550,  0xcee421a1fca0fdde,  0x42330a2d2384851,  0x42953fa3c8bbd0df,
  0x8db012a48e153f52,  0xcb061da59496a7dc,  0x1c10ca6ba0e1253,  0x477703a7a08d8add,
  0x828b56a8364fd154,  0xc43d59a92ccc49da,  0xefa48aa0254fc55,  0x484c47ab18d764db,
  0x87696aac5e798b56,  0xc1df65ad44fa13d8,  0xb1874ae6a62a657,  0x4dae7baf70e13ed9,
  0x9cfddeb05bfb1058,  0xda4bd1b1417888d6,  0x108cc0b26fe03d59,  0x563acfb37563a5d7,
  0x991fe2b433cd4a5a,  0xdfa9edb5294ed2d4,  0x156efcb607d6675b,  0x53d8f3b71d55ffd5,
  0x9624a6b88b97a45c,  0xd092a9b991143cd2,  0x1a55b8babf8c895d,  0x5ce3b7bba50f11d3,
  0x93c69abce3a1fe5e,  0xd57095bdf92266d0,  0x1fb784bed7bad35f,  0x59018bbfcd394bd1,
  0xf09734c04fc94660,  0xb6213bc1554adeee,  0x7ce62ac27bd26b61,  0x3a5025c36151f3ef,
  0xf57508c427ff1c62,  0xb3c307c53d7c84ec,  0x790416c613e43163,  0x3fb219c70967a9ed,
  0xfa4e4cc89fa5f264,  0xbcf843c985266aea,  0x763f52caabbedf65,  0x30895dcbb13d47eb,
  0xffac70ccf793a866,  0xb91a7fcded1030e8,  0x73dd6ecec3888567,  0x356b61cfd90b1de9,
  0xe438c4d0f2113368,  0xa28ecbd1e892abe6,  0x6849dad2c60a1e69,  0x2effd5d3dc8986e7,
  0xe1daf8d49a27696a,  0xa76cf7d580a4f1e4,  0x6dabe6d6ae3c446b,  0x2b1de9d7b4bfdce5,
  0xeee1bcd8227d876c,  0xa857b3d938fe1fe2,  0x6290a2da1666aa6d,  0x2426addb0ce532e3,
  0xeb0380dc4a4bdd6e,  0xadb58fdd50c845e0,  0x67729ede7e50f06f,  0x21c491df64d368e1,
  0xd8d4c9e02864ac70,  0x9e62c6e132e734fe,  0x54a5d7e21c7f8171,  0x1213d8e306fc19ff,
  0xdd36f5e44052f672,  0x9b80fae55ad16efc,  0x5147ebe67449db73,  0x17f1e4e76eca43fd,
  0xd20db1e8f8081874,  0x94bbbee9e28b80fa,  0x5e7cafeacc133575,  0x18caa0ebd690adfb,
  0xd7ef8dec903e4276,  0x915982ed8abddaf8,  0x5b9e93eea4256f77,  0x1d289cefbea6f7f9,
  0xcc7b39f095bcd978,  0x8acd36f18f3f41f6,  0x400a27f2a1a7f479,  0x6bc28f3bb246cf7,
  0xc99905f4fd8a837a,  0x8f2f0af5e7091bf4,  0x45e81bf6c991ae7b,  0x35e14f7d31236f5,
  0xc6a241f845d06d7c,  0x80144ef95f53f5f2,  0x4ad35ffa71cb407d,  0xc6550fb6b48d8f3,
  0xc3407dfc2de6377e,  0x85f672fd3765aff0,  0x4f3163fe19fd1a7f,  0x9876cff037e82f1,
  },{
  0x0000000000000000,  0x83478b07b2468764,  0x1b8e0b0e798c13c8,  0x98c98009cbca94ac,
  0x3601161cf205268d,  0xb5469d1b4043a1e9,  0x2d8f1d128b893545,  0xaec8961539cfb221,
  0x6c022c38f90a4c07,  0xef45a73f4b4ccb63,  0x778c273680865fcf,  0xf4cbac3132c0d8ab,
  0x5a033a240b0f6a8a,  0xd944b123b949edee,  0x418d312a72837942,  0xc2caba2dc0c5fe26,
  0xd8045870ef14980e,  0x5b43d3775d521f6a,  0xc38a537e96988bc6,  0x40cdd87924de0ca2,
  0xee054e6c1d11be83,  0x6d42c56baf5739e7,  0xf58b4562649dad4b,  0x76ccce65d6db2a2f,
  0xb4067448161ed409,  0x3741ff4fa458536d,  0xaf887f466f92c7c1,  0x2ccff441ddd440a5,
  0x82076254e41bf284,  0x140e953565d75e0,  0x9989695a9d97e14c,  0x1acee25d2fd16628,
  0xad08b0e0c3282d1c,  0x2e4f3be7716eaa78,  0xb686bbeebaa43ed4,  0x35c130e908e2b9b0,
  0x9b09a6fc312d0b91,  0x184e2dfb836b8cf5,  0x8087adf248a11859,  0x3c026f5fae79f3d,
  0xc10a9cd83a22611b,  0x424d17df8864e67f,  0xda8497d643ae72d3,  0x59c31cd1f1e8f5b7,
  0xf70b8ac4c8274796,  0x744c01c37a61c0f2,  0xec8581cab1ab545e,  0x6fc20acd03edd33a,
  0x750ce8902c3cb512,  0xf64b63979e7a3276,  0x6e82e39e55b0a6da,  0xedc56899e7f621be,
  0x430dfe8cde39939f,  0xc04a758b6c7f14fb,  0x5883f582a7b58057,  0xdbc47e8515f30733,
  0x190ec4a8d536f915,  0x9a494faf67707e71,  0x280cfa6acbaeadd,  0x81c744a11efc6db9,
  0x2f0fd2b42733df98,  0xac4859b3957558fc,  0x3481d9ba5ebfcc50,  0xb7c652bdecf94b34,
  0x47107ddd9b505a38,  0xc457f6da2916dd5c,  0x5c9e76d3e2dc49f0,  0xdfd9fdd4509ace94,
  0x71116bc169557cb5,  0xf256e0c6db13fbd1,  0x6a9f60cf10d96f7d,  0xe9d8ebc8a29fe819,
  0x2b1251e5625a163f,  0xa855dae2d01c915b,  0x309c5aeb1bd605f7,  0xb3dbd1eca9908293,
  0x1d1347f9905f30b2,  0x9e54ccfe2219b7d6,  0x69d4cf7e9d3237a,  0x85dac7f05b95a41e,
  0x9f1425ad7444c236,  0x1c53aeaac6024552,  0x849a2ea30dc8d1fe,  0x7dda5a4bf8e569a,
  0xa91533b18641e4bb,  0x2a52b8b6340763df,  0xb29b38bfffcdf773,  0x31dcb3b84d8b7017,
  0xf31609958d4e8e31,  0x705182923f080955,  0xe898029bf4c29df9,  0x6bdf899c46841a9d,
  0xc5171f897f4ba8bc,  0x4650948ecd0d2fd8,  0xde99148706c7bb74,  0x5dde9f80b4813c10,
  0xea18cd3d58787724,  0x695f463aea3ef040,  0xf196c63321f464ec,  0x72d14d3493b2e388,
  0xdc19db21aa7d51a9,  0x5f5e5026183bd6cd,  0xc797d02fd3f14261,  0x44d05b2861b7c505,
  0x861ae105a1723b23,  0x55d6a021334bc47,  0x9d94ea0bd8fe28eb,  0x1ed3610c6ab8af8f,
  0xb01bf71953771dae,  0x335c7c1ee1319aca,  0xab95fc172afb0e66,  0x28d2771098bd8902,
  0x321c954db76cef2a,  0xb15b1e4a052a684e,  0x29929e43cee0fce2,  0xaad515447ca67b86,
  0x041d83514569c9a7,  0x875a0856f72f4ec3,  0x1f93885f3ce5da6f,  0x9cd403588ea35d0b,
  0x5e1eb9754e66a32d,  0xdd593272fc202449,  0x4590b27b37eab0e5,  0xc6d7397c85ac3781,
  0x681faf69bc6385a0,  0xeb58246e0e2502c4,  0x7391a467c5ef9668,  0xf0d62f6077a9110c,
  0x8e20faa72ba0b470,  0xd6771a099e63314,  0x95aef1a9522ca7b8,  0x16e97aaee06a20dc,
  0xb821ecbbd9a592fd,  0x3b6667bc6be31599,  0xa3afe7b5a0298135,  0x20e86cb2126f0651,
  0xe222d69fd2aaf877,  0x61655d9860ec7f13,  0xf9acdd91ab26ebbf,  0x7aeb569619606cdb,
  0xd423c08320afdefa,  0x57644b8492e9599e,  0xcfadcb8d5923cd32,  0x4cea408aeb654a56,
  0x5624a2d7c4b42c7e,  0xd56329d076f2ab1a,  0x4daaa9d9bd383fb6,  0xceed22de0f7eb8d2,
  0x6025b4cb36b10af3,  0xe3623fcc84f78d97,  0x7babbfc54f3d193b,  0xf8ec34c2fd7b9e5f,
  0x3a268eef3dbe6079,  0xb96105e88ff8e71d,  0x21a885e1443273b1,  0xa2ef0ee6f674f4d5,
  0x0c2798f3cfbb46f4,  0x8f6013f47dfdc190,  0x17a993fdb637553c,  0x94ee18fa0471d258,
  0x23284a47e888996c,  0xa06fc1405ace1e08,  0x38a6414991048aa4,  0xbbe1ca4e23420dc0,
  0x15295c5b1a8dbfe1,  0x966ed75ca8cb3885,  0xea757556301ac29,  0x8de0dc52d1472b4d,
  0x4f2a667f1182d56b,  0xcc6ded78a3c4520f,  0x54a46d71680ec6a3,  0xd7e3e676da4841c7,
  0x792b7063e387f3e6,  0xfa6cfb6451c17482,  0x62a57b6d9a0be02e,  0xe1e2f06a284d674a,
  0xfb2c1237079c0162,  0x786b9930b5da8606,  0xe0a219397e1012aa,  0x63e5923ecc5695ce,
  0xcd2d042bf59927ef,  0x4e6a8f2c47dfa08b,  0xd6a30f258c153427,  0x55e484223e53b343,
  0x972e3e0ffe964d65,  0x1469b5084cd0ca01,  0x8ca03501871a5ead,  0xfe7be06355cd9c9,
  0xa12f28130c936be8,  0x2268a314bed5ec8c,  0xbaa1231d751f7820,  0x39e6a81ac759ff44,
  0xc930877ab0f0ee48,  0x4a770c7d02b6692c,  0xd2be8c74c97cfd80,  0x51f907737b3a7ae4,
  0xff31916642f5c8c5,  0x7c761a61f0b34fa1,  0xe4bf9a683b79db0d,  0x67f8116f893f5c69,
  0xa532ab4249faa24f,  0x26752045fbbc252b,  0xbebca04c3076b187,  0x3dfb2b4b823036e3,
  0x9333bd5ebbff84c2,  0x1074365909b903a6,  0x88bdb650c273970a,  0xbfa3d577035106e,
  0x1134df0a5fe47646,  0x9273540deda2f122,  0xabad4042668658e,  0x89fd5f03942ee2ea,
  0x2735c916ade150cb,  0xa47242111fa7d7af,  0x3cbbc218d46d4303,  0xbffc491f662bc467,
  0x7d36f332a6ee3a41,  0xfe71783514a8bd25,  0x66b8f83cdf622989,  0xe5ff733b6d24aeed,
  0x4b37e52e54eb1ccc,  0xc8706e29e6ad9ba8,  0x50b9ee202d670f04,  0xd3fe65279f218860,
  0x6438379a73d8c354,  0xe77fbc9dc19e4430,  0x7fb63c940a54d09c,  0xfcf1b793b81257f8,
  0x5239218681dde5d9,  0xd17eaa81339b62bd,  0x49b72a88f851f611,  0xcaf0a18f4a177175,
  0x083a1ba28ad28f53,  0x8b7d90a538940837,  0x13b410acf35e9c9b,  0x90f39bab41181bff,
  0x3e3b0dbe78d7a9de,  0xbd7c86b9ca912eba,  0x25b506b0015bba16,  0xa6f28db7b31d3d72,
  0xbc3c6fea9ccc5b5a,  0x3f7be4ed2e8adc3e,  0xa7b264e4e5404892,  0x24f5efe35706cff6,
  0x8a3d79f66ec97dd7,  0x97af2f1dc8ffab3,  0x91b372f817456e1f,  0x12f4f9ffa503e97b,
  0xd03e43d265c6175d,  0x5379c8d5d7809039,  0xcbb048dc1c4a0495,  0x48f7c3dbae0c83f1,
  0xe63f55ce97c331d0,  0x6578dec92585b6b4,  0xfdb15ec0ee4f2218,  0x7ef6d5c75c09a57c,
  }
 };
/*! \brief SHA3. значение раундовых констант */
const static ak_uint64 keccakf_rc[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};
/*! \brief SHA3. значения для сдвигов в перестановках ρ и π */
const static int keccakf_ro[24] =
        {
                1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
        };
const static int keccakf_pi[24] =
        {
                10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
        };

/* ---------------------------------------------------------------------------------------------- */
/*! \brief 16-я степень сопровождающей матрицы линейного регистра сдвига, определяемого в
    алгоритме Кузнечик (ГОСТ Р 34.12-2015). */
/* ---------------------------------------------------------------------------------------------- */
 const static ak_uint8 L[16][16] = {
 { 0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94 },
 { 0x94, 0xA5, 0x3C, 0x44, 0xD1, 0x8D, 0xB4, 0x54, 0xDE, 0x6F, 0x77, 0x5D, 0x96, 0x74, 0x2D, 0x84 },
 { 0x84, 0x64, 0x48, 0xDF, 0xD3, 0x31, 0xA6, 0x30, 0xE0, 0x5A, 0x44, 0x97, 0xCA, 0x75, 0x99, 0xDD },
 { 0xDD, 0x0D, 0xF8, 0x52, 0x91, 0x64, 0xFF, 0x7B, 0xAF, 0x3D, 0x94, 0xF3, 0xD9, 0xD0, 0xE9, 0x10 },
 { 0x10, 0x89, 0x48, 0x7F, 0x91, 0xEC, 0x39, 0xEF, 0x10, 0xBF, 0x60, 0xE9, 0x30, 0x5E, 0x95, 0xBD },
 { 0xBD, 0xA2, 0x48, 0xC6, 0xFE, 0xEB, 0x2F, 0x84, 0xC9, 0xAD, 0x7C, 0x1A, 0x68, 0xBE, 0x9F, 0x27 },
 { 0x27, 0x7F, 0xC8, 0x98, 0xF3, 0x0F, 0x54, 0x08, 0xF6, 0xEE, 0x12, 0x8D, 0x2F, 0xB8, 0xD4, 0x5D },
 { 0x5D, 0x4B, 0x8E, 0x60, 0x01, 0x2A, 0x6C, 0x09, 0x49, 0xAB, 0x8D, 0xCB, 0x14, 0x87, 0x49, 0xB8 },
 { 0xB8, 0x6E, 0x2A, 0xD4, 0xB1, 0x37, 0xAF, 0xD4, 0xBE, 0xF1, 0x2E, 0xBB, 0x1A, 0x4E, 0xE6, 0x7A },
 { 0x7A, 0x16, 0xF5, 0x52, 0x78, 0x99, 0xEB, 0xD5, 0xE7, 0xC4, 0x2D, 0x06, 0x17, 0x62, 0xD5, 0x48 },
 { 0x48, 0xC3, 0x02, 0x0E, 0x58, 0x90, 0xE1, 0xA3, 0x6E, 0xAF, 0xBC, 0xC5, 0x0C, 0xEC, 0x76, 0x6C },
 { 0x6C, 0x4C, 0xDD, 0x65, 0x01, 0xC4, 0xD4, 0x8D, 0xA4, 0x02, 0xEB, 0x20, 0xCA, 0x6B, 0xF2, 0x72 },
 { 0x72, 0xE8, 0x14, 0x07, 0x49, 0xF6, 0xD7, 0xA6, 0x6A, 0xD6, 0x11, 0x1C, 0x0C, 0x10, 0x33, 0x76 },
 { 0x76, 0xE3, 0x30, 0x9F, 0x6B, 0x30, 0x63, 0xA1, 0x2B, 0x1C, 0x43, 0x68, 0x70, 0x87, 0xC8, 0xA2 },
 { 0xA2, 0xD0, 0x44, 0x86, 0x2D, 0xB8, 0x64, 0xC1, 0x9C, 0x89, 0x48, 0x90, 0xDA, 0xC6, 0x20, 0x6E },
 { 0x6E, 0x4D, 0x8E, 0xEA, 0xA9, 0xF6, 0xBF, 0x0A, 0xF3, 0xF2, 0x8E, 0x93, 0xBF, 0x74, 0x98,  0xCF }
};

/* ---------------------------------------------------------------------------------------------- */
/*! \brief 16-я степень обратной матрицы к сопровождающей матрице линейного регистра сдвига,
     определяемого в алгоритме Кузнечик (ГОСТ Р 34.12-2015). */
/* ---------------------------------------------------------------------------------------------- */
 const static ak_uint8 Linv[16][16]  = {
 { 0xCF, 0x98, 0x74, 0xBF, 0x93, 0x8E, 0xF2, 0xF3, 0x0A, 0xBF, 0xF6, 0xA9, 0xEA, 0x8E, 0x4D, 0x6E },
 { 0x6E, 0x20, 0xC6, 0xDA, 0x90, 0x48, 0x89, 0x9C, 0xC1, 0x64, 0xB8, 0x2D, 0x86, 0x44, 0xD0, 0xA2 },
 { 0xA2, 0xC8, 0x87, 0x70, 0x68, 0x43, 0x1C, 0x2B, 0xA1, 0x63, 0x30, 0x6B, 0x9F, 0x30, 0xE3, 0x76 },
 { 0x76, 0x33, 0x10, 0x0C, 0x1C, 0x11, 0xD6, 0x6A, 0xA6, 0xD7, 0xF6, 0x49, 0x07, 0x14, 0xE8, 0x72 },
 { 0x72, 0xF2, 0x6B, 0xCA, 0x20, 0xEB, 0x02, 0xA4, 0x8D, 0xD4, 0xC4, 0x01, 0x65, 0xDD, 0x4C, 0x6C },
 { 0x6C, 0x76, 0xEC, 0x0C, 0xC5, 0xBC, 0xAF, 0x6E, 0xA3, 0xE1, 0x90, 0x58, 0x0E, 0x02, 0xC3, 0x48 },
 { 0x48, 0xD5, 0x62, 0x17, 0x06, 0x2D, 0xC4, 0xE7, 0xD5, 0xEB, 0x99, 0x78, 0x52, 0xF5, 0x16, 0x7A },
 { 0x7A, 0xE6, 0x4E, 0x1A, 0xBB, 0x2E, 0xF1, 0xBE, 0xD4, 0xAF, 0x37, 0xB1, 0xD4, 0x2A, 0x6E, 0xB8 },
 { 0xB8, 0x49, 0x87, 0x14, 0xCB, 0x8D, 0xAB, 0x49, 0x09, 0x6C, 0x2A, 0x01, 0x60, 0x8E, 0x4B, 0x5D },
 { 0x5D, 0xD4, 0xB8, 0x2F, 0x8D, 0x12, 0xEE, 0xF6, 0x08, 0x54, 0x0F, 0xF3, 0x98, 0xC8, 0x7F, 0x27 },
 { 0x27, 0x9F, 0xBE, 0x68, 0x1A, 0x7C, 0xAD, 0xC9, 0x84, 0x2F, 0xEB, 0xFE, 0xC6, 0x48, 0xA2, 0xBD },
 { 0xBD, 0x95, 0x5E, 0x30, 0xE9, 0x60, 0xBF, 0x10, 0xEF, 0x39, 0xEC, 0x91, 0x7F, 0x48, 0x89, 0x10 },
 { 0x10, 0xE9, 0xD0, 0xD9, 0xF3, 0x94, 0x3D, 0xAF, 0x7B, 0xFF, 0x64, 0x91, 0x52, 0xF8, 0x0D, 0xDD },
 { 0xDD, 0x99, 0x75, 0xCA, 0x97, 0x44, 0x5A, 0xE0, 0x30, 0xA6, 0x31, 0xD3, 0xDF, 0x48, 0x64, 0x84 },
 { 0x84, 0x2D, 0x74, 0x96, 0x5D, 0x77, 0x6F, 0xDE, 0x54, 0xB4, 0x8D, 0xD1, 0x44, 0x3C, 0xA5, 0x94 },
 { 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01 }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 256-ти битной эллиптической кривой из тестового примера ГОСТ Р 34.10-2012 (Приложение А.1). */
/*! \code
      a = "7",
      b = "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
      p = "8000000000000000000000000000000000000000000000000000000000000431",
      q = "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
     px = "2",
     py = "8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static const struct wcurve id_tc26_gost3410_2012_256_test_paramset = {
  ak_mpzn256_size,
  1,
  { 0xffffffffffffc983, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff }, /* a */
  { 0x807bbfa323a3952a, 0x004469b4541a2542, 0x20391abe272c66ad, 0x58df983a171cd5ae }, /* b */
  { 0x0000000000000431, 0x0000000000000000, 0x0000000000000000, 0x8000000000000000 }, /* p */
  { 0x0000000000464584, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* r2 */
  { 0xc59cfc193accf5b3, 0x50fe8a1892976154, 0x0000000000000001, 0x8000000000000000 }, /* q */
  { 0xecaed44677f7f28d, 0x4af1f8ac73c6c555, 0xc0db8b05c83ad16a, 0x6e749e5b503b112a }, /* r2q */
  {
    { 0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* px */
    { 0x2b96abbcea7e8fc8, 0x85c97f0a9ca26712, 0xbd6316030e16d19c, 0x08e2a8a0e65147d4 }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0xdbf951d5883b2b2fLL, /* n */
  0x66ff43a234713e85LL /* nq */
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 256-ти битной эллиптической кривой из рекомендаций Р 50.1.114-2016 (paramSetA). */
/*! \code
      a = "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
      b = "295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513",
      p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
      q = "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67",
     px = "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
     py = "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C",
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static const struct wcurve id_tc26_gost3410_2012_256_paramsetA = {
  ak_mpzn256_size,
  4, /* cofactor */
  { 0x6d0078e62fc81048, 0x94db4f98bfb73698, 0x75e9b60631449efd, 0xca0709cc398e1cd1 }, /* a */
  { 0xacd1216d5cc63966, 0x534b728e6773c810, 0xfb4e95d31a5032fe, 0xb76e3775f6a4aee7 }, /* b */
  { 0xfffffffffffffd97, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff }, /* p */
  { 0x000000000005cf11, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* r2 */
  { 0xc115af556c360c67, 0x0fd8cddfc87b6635, 0x0000000000000000, 0x4000000000000000 }, /* q */
  { 0x57cb446240dd1710, 0x7556091c4805caa4, 0xd0593365f9384bcd, 0x0fb1fbc48b0f0eb4 }, /* r2q */
  {
    { 0x8b2582fe742daa28, 0x658b9196932e02c7, 0x880923425712b2bb, 0x91e38443a5e82c0d }, /* px */
    { 0xaf268adb32322e5c, 0x5fde0b5344766740, 0x895786c4bb46e956, 0x32879423ab1a0375 }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0x46f3234475d5add9LL, /* n */
  0x035bdd1aeafdb0a9LL /* nq */
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 256-ти битной эллиптической кривой, определяемые RFC-4357, set A (вариант КриптоПро). */
/*! \code
      a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
      b = "A6",
      p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
      q = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
     px = "1",
     qx = "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static const struct wcurve id_rfc4357_gost3410_2001_paramsetA = {
  ak_mpzn256_size,
  1,
  { 0xfffffffffffff65c, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff }, /* a */
  { 0x0000000000019016, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* b */
  { 0xfffffffffffffd97, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff }, /* p */
  { 0x000000000005cf11, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* r2 */
  { 0x45841b09b761b893, 0x6c611070995ad100, 0xffffffffffffffff, 0xffffffffffffffff }, /* q */
  { 0x9ac2d7858e79a469, 0xfb07f8222e76dd52, 0xf74885d08a3714c6, 0x551fe9cb451179db }, /* r2q */
  {
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* px */
    { 0x22acc99c9e9f1e14, 0x35294f2ddf23e3b1, 0x27df505a453f2b76, 0x8d91e471e0989cda }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0x46f3234475d5add9LL, /* n */
  0x9ee6ea0b57c7da65LL /* nq */
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 256-ти битной эллиптической кривой, определяемые RFC-4357, set B (вариант КриптоПро). */
/*! \code
      a = "8000000000000000000000000000000000000000000000000000000000000C96",
      b = "3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B",
      p = "8000000000000000000000000000000000000000000000000000000000000C99",
      q = "800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F",
     px = "1",
     py = "3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC"
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static const struct wcurve id_rfc4357_gost3410_2001_paramsetB = {
  ak_mpzn256_size,
  1,
  { 0x0000000000004b96, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* a */
  { 0x8dcc455aa9c5a084, 0x91ab42df6cf438a8, 0x8f8aa907eeac7d11, 0x3ce5d221f6285375 }, /* b */
  { 0x0000000000000c99, 0x0000000000000000, 0x0000000000000000, 0x8000000000000000 }, /* p */
  { 0x00000000027acdc4, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* r2 */
  { 0xe497161bcc8a198f, 0x5f700cfff1a624e5, 0x0000000000000001, 0x8000000000000000 }, /* q */
  { 0x29b721f4e6cd7823, 0x2a3104a7ea43e855, 0x4a2e7e2f6882cf10, 0x09d1d2c4e5082466 }, /* r2q */
  {
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* px */
    { 0x744bf8d717717efc, 0xc545c9858d03ecfb, 0xb83d1c3eb2c070e5, 0x3fa8124359f96680 }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0xbd667ab8a3347857LL, /* n */
  0xca89614990611a91LL /* nq */
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 256-ти битной эллиптической кривой, определяемые RFC-4357, set C (вариант КриптоПро). */
/*! \code
       a = "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
       b = "805A",
       p = "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
       q = "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
      px = "0",
      py = "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67"
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static const struct wcurve id_rfc4357_gost3410_2001_paramsetC = {
  ak_mpzn256_size,
  1,
  { 0x5ffcd69d0ae34c07, 0x0d9628a05ad19921, 0x5799e9d81848eb56, 0x0a1ce1dcc49b8526 }, /* a */
  { 0x4be8a4e93bda2acf, 0x79cc0e3e90d382dd, 0x3ba4c8b01d9cc79b, 0x5cc73b5a966609e9 }, /* b */
  { 0x7998f7b9022d759b, 0xcf846e86789051d3, 0xab1ec85e6b41c8aa, 0x9b9f605f5a858107 }, /* p */
  { 0x409973b4c427fcea, 0x1017bb39c2d346c5, 0x186304212849c07b, 0x807a394ede097652 }, /* r2 */
  { 0xf02f3a6598980bb9, 0x582ca3511eddfb74, 0xab1ec85e6b41c8aa, 0x9b9f605f5a858107 }, /* q */
  { 0xe94faab66aba180e, 0x04fda8694afda24b, 0xc67e5d0ee96e8ed3, 0x7aa61b49a49d4759 }, /* r2q */
  {
    { 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* px */
    { 0x366e550dfdb3bb67, 0x4d4dc440d4641a8f, 0x3cbf3783cd08c0ee, 0x41ece55743711a8c }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0xdf6e6c2c727c176dLL, /* n */
  0xa1c6af0a552f7577LL /* nq */
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 256-ти битной эллиптической кривой выработанные авторами библиотеки (paramSetA). */
/*! \code
      a = "80008EAE551953AA1E07CF9A8DCCF9415BB77DE434D0AE9633E33DA2F1EA88D9",
      b = "B2A49D5ADCC33A6693F21A71CD49B376D79B33655D9071CF6DB57BCA67E21B",
      p = "80008EAE551953AA1E07CF9A8DCCF9415BB77DE434D0AE9633E33DA2F1EA88DB",
      q = "80008EAE551953AA1E07CF9A8DCCF942B24C7D30A656C695299C1ED853D129F1",
     px = "1",
     qx = "50AD006962FA5D1E6C1B6506ACB81C4C7DC1A0B4ECCC5224083AF1D2BBAD5116"
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static const struct wcurve id_axel_gost3410_2012_256_paramsetA = {
  ak_mpzn256_size,
  1,
  { 0xcf8cf68bc7aa236c, 0x6eddf790d342ba58, 0x781f3e6a3733e505, 0x00023ab954654ea8 }, /* a */
  { 0x560020c5e85d6e00, 0x149565e889215788, 0x5aa364f74663be3b, 0x14ba0ee9c98bc6a2 }, /* b */
  { 0x33e33da2f1ea88db, 0x5bb77de434d0ae96, 0x1e07cf9a8dccf941, 0x80008eae551953aa }, /* p */
  { 0x93189730fd45fede, 0xac7513dbc87fef31, 0x614cafbadb0cddb4, 0x2303790d5067be5d }, /* r2 */
  { 0x299c1ed853d129f1, 0xb24c7d30a656c695, 0x1e07cf9a8dccf942, 0x80008eae551953aa }, /* q */
  { 0x053a94a83d077055, 0xe8002ffbf5cdbc94, 0xe5908ace6a4f46af, 0x79f340513f7d85d9 }, /* r2q */
  {
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* px */
    { 0x083af1d2bbad5116, 0x7dc1a0b4eccc5224, 0x6c1b6506acb81c4c, 0x50ad006962fa5d1e }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0xe39d517a9b49ccadLL, /* n */
  0x56407ad9f73f58efLL /* nq */
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 512-ти битной эллиптической кривой из тестового примера ГОСТ Р 34.10-2012 (Приложение А.2). */
/*! \code
      a = "7",
      b = "1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC",
      p = "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373",
      q = "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF",
     px = "24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A",
     py = "2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E",
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static const struct wcurve id_tc26_gost3410_2012_512_test_paramset = {
  ak_mpzn512_size,
  1,
  { 0xd029a50f056849c5, 0xc102fa1830a665e5, 0x93678fa569b3c155, 0x61dff2a95e2108c5, 0x3500e30d3e698dd3, 0xb9cafa8506ed8887, 0xb1b73df28851b571, 0x3e261f7e31fc8188 }, /* a */
  { 0x3d869f8d06cde456, 0x22167b920ce0bfcb, 0xf7fdd636df3cc250, 0x45228319a5e6292d, 0xfd513828d9ad288d, 0xc7d45cb277e670aa, 0x04890c718bc5c744, 0x1a693f403fc50f21 }, /* b */
  { 0x1664bbf528be6373, 0x35b8336fac224dd8, 0x0458047e80e4546d, 0xf1d852741af4704a, 0xd4eb7c09b5d2d15d, 0x922b14b2ffb90f04, 0x550d267b6b2fee80, 0x4531acd1fe0023c7 }, /* p */
  { 0x001c10bc2d005b65, 0x4b907a71e647ee63, 0xe417d58d200c2aa0, 0x0815b9eb1e7dd300, 0xca0bc8af77c8690a, 0xfcd983cfb7c663d9, 0x01fde9ca99de0852, 0x1d887dcd9cd19c10 }, /* r2 */
  { 0xd644aaf187e6e6df, 0xd86e25edbe23c595, 0x19905c5eecc423f1, 0xa82f2d7ecb1dbac7, 0xd4eb7c09b5d2d15d, 0x922b14b2ffb90f04, 0x550d267b6b2fee80, 0x4531acd1fe0023c7 }, /* q */
  { 0xb03174e56db6ba90, 0x561500cb39a9b66b, 0x929e0924887fab48, 0xe23c04dc39c8c930, 0x0cc44723bcc36979, 0xd70dfcccc3dd062f, 0x80bc9d923a08f9a9, 0x3057350e3201bb36 }, /* r2q */
  {
    { 0xb530f1b120248a9a, 0x8bc849977fac33b4, 0xc6b60aa7eee804e2, 0xfd60611262cd838d, 0x25f91093a68cd762, 0x5213b3b3d7057cc8, 0xf396bf6ebbfd7a6c, 0x24d19cc64572ee30 }, /* px */
    { 0x6dbb92cb1add371e, 0xdc1a18b91b24640b, 0xf7eb3351e1ee4e43, 0x83ab156d77f1496b, 0xf32447c259f39b2c, 0xcfbf061e91e5f2c3, 0x0d020613c857acdd, 0x2bb312a43bd2ce6e }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0xd6412ff7c29b8645LL, /* n */
  0x50bc7d084a21aae1LL /* nq */
 };


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 512-ти битной эллиптической кривой из рекомендаций Р 50.1.114-2016 (paramSetA). */
/*! \code
      a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4",
      b = "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
      p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
      q = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275",
     px = "3",
     py = "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4",
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static const struct wcurve id_tc26_gost3410_2012_512_paramsetA = {
  ak_mpzn512_size,
  1,
  { 0xfffffffffffff71c, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff }, /* a */
  { 0x3e2a1b8106e8a17d, 0x3e694a40649ca74b, 0x7cd5ed6575cbfc5f, 0x84e4722c383c8743, 0x9527086e6e4db48e, 0x2d4b3fda85c534b6, 0x9d2dd3769d088dff, 0x57e4a0c5f647c2e3 }, /* b */
  { 0xfffffffffffffdc7, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff }, /* p */
  { 0x000000000004f0b1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* r2 */
  { 0xcacdb1411f10b275, 0x9b4b38abfad2b85d, 0x6ff22b8d4e056060, 0x27e69532f48d8911, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff }, /* q */
  { 0x546775b92106e979, 0xb55cd33800ab10e6, 0x80b08b27e9cebbc7, 0xa06b76a2bae6fc86, 0xc7433579e382956f, 0xbab8be5dd7b1651d, 0xee028bf9d8ed3314, 0xb66ae6c00bebd6c3 }, /* r2q */
  {
    { 0x0000000000000003, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* px */
    { 0x89a589cb5215f2a4, 0x8028fe5fc235f5b8, 0x3d75e6a50e3a41e9, 0xdf1626be4fd036e9, 0x778064fdcbefa921, 0xce5e1c93acf1abc1, 0xa61b8816e25450e6, 0x7503cfe87a836ae3 }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0x58a1f7e6ce0f4c09LL, /* n */
  0x02ccc1665d51f223LL /* nq */
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 512-ти битной эллиптической кривой из рекомендаций Р 50.1.114-2016 (paramSetB). */
/*! \code
      a = "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C",
      b = "687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116",
      p = "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F",
      q = "800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD",
     px = "2",
     py = "1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD",
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static const struct wcurve id_tc26_gost3410_2012_512_paramsetB = {
  ak_mpzn512_size,
  1,
  { 0x000000000000029a, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* a */
  { 0xdbe748c318a75dd6, 0xc954a7809097bfc1, 0x6553cd27e2d5a471, 0xb99b326049435cf3, 0xe9eac8a216d2c5e7, 0x260b45a102d0cc51, 0x8636181d6c5bd56d, 0x638259a12c5765bc }, /* b */
  { 0x000000000000006f, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8000000000000000 }, /* p */
  { 0x000000000000c084, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* r2 */
  { 0xc6346c54374f25bd, 0x8b996712101bea0e, 0xacfdb77bd9d40cfa, 0x49a1ec142565a545, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x8000000000000000 }, /* q */
  { 0x3163da9749d3cb8b, 0x267d56905313f38b, 0xc55538cf997acac4, 0xb1532b08f1e25e5c, 0xc385980eb887a3f9, 0x9f96043308eeb401, 0xf96232d7a52b18fe, 0x21c65cda4cadccc0 }, /* r2q */
  {
    { 0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* px */
    { 0x7e21340780fe41bd, 0x28041055f94ceeec, 0x152cbcaaf8c03988, 0xdcb228fd1edf4a39, 0xbe6dd9e6c8ec7335, 0x3c123b697578c213, 0x2c071e3647a8940f, 0x1a8f7eda389b094c }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0x4e6a171024e6a171LL, /* n */
  0xc07d62492cbac26bLL /* nq */
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 512-ти битной эллиптической кривой из рекомендаций Р 50.1.114-2016 (paramSetC). */
/*! \code
      a = "DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3",
      b = "B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1",
      p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
      q = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED",
     px = "E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148",
     py = "F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F",
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static const struct wcurve id_tc26_gost3410_2012_512_paramsetC = {
  ak_mpzn512_size,
  4,
  { 0xd341ab3699869915, 0x3d6c9273ccebc4c1, 0x486b484c83cb0726, 0x9a8145b812d1a7b0, 0x2003251cadf8effa, 0x6b20d9f8b7db94f1, 0xdd0c19f57c9cc019, 0x408aa82ae77985ca }, /* a */
  { 0xb304002a3c03ce62, 0xcbe7bfdf359dc095, 0x57398fea29abadad, 0x3ce46aec38657034, 0xabf0edb5e37f775e, 0x63ccffc5280e7697, 0x6754d90e93579656, 0xc9b558b380cc6f00 }, /* b */
  { 0xfffffffffffffdc7, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff }, /* p */
  { 0x000000000004f0b1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* r2 */
  { 0x94623cef47f023ed, 0xc8eda9e7a769a126, 0x4c33a9ff5147502c, 0xc98cdba46506ab00, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff }, /* q */
  { 0xe58fa18ee6ca4eb6, 0xe79280282d956fca, 0xd016086ec2d4f903, 0x542f8f3fa490666a, 0x04f77045db49adc9, 0x314e0a57f445b20e, 0x8910352f3bea2192, 0x394c72054d8503be }, /* r2q */
  {
    { 0xc5bc7928c1950148, 0xc6fb85487eae97aa, 0xa7b9033db9ed3610, 0xa27272a7ae602bf2, 0xd385f7074cea043a, 0x2295b7a9cbaef021, 0xebe241ce593ef5de, 0xe2e31edfc23de7bd }, /* px */
    { 0xd0396e9a9addc40f, 0x04f726aa854bae07, 0xef32d85822423b63, 0xe18e2d33e3021ed2, 0x8c108c3d2090ff9b, 0x7939804d6527378b, 0xabbccff5911cb857, 0xf5ce40d95b5eb899 }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0x58a1f7e6ce0f4c09LL, /* n */
  0x0ed9d8e0b6624e1bLL /* nq */
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 512-ти битной эллиптической кривой выработанные авторами библиотеки (paramSetA). */
/*! \code
      a = "80007C0D100DE1DA4C082D55B224E1F6995C0200BAE1827110D0CE783E5EBD08AFACCA5A732368521E0BAD88865E21DA43DA42B35757B8038768059BE89E36AD",
      b = "7633E0B39500943957990D315BE1F4B2B971527863EB30D9D1A0B52A8489484212502F709F1D067DFC109E06AF608B8DD4F854E4F45DF4309506452C499A102D",
      p = "80007C0D100DE1DA4C082D55B224E1F6995C0200BAE1827110D0CE783E5EBD08AFACCA5A732368521E0BAD88865E21DA43DA42B35757B8038768059BE89E36AF",
      q = "80007C0D100DE1DA4C082D55B224E1F6995C0200BAE1827110D0CE783E5EBD091D1C41E039FB32B9D6115C0919412876018EF3923B4255F8717DB632094F9B5B",
     px = "3",
     py = "3F1F3A51B164FFC05E7221D67A01B361870727C3DF007D3A9FDB7A1E9230F0781D69806E0CC5E38CB62B18E2D6D4BCF12112F42600D5783AE109F64B0D2845B5",
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static const struct wcurve id_axel_gost3410_2012_512_paramsetA = {
  ak_mpzn512_size,
  1,
  { 0x1da0166fa278dabc, 0x0f690acd5d5ee00e, 0x782eb62219788769, 0xbeb32969cc8da148, 0x434339e0f97af422, 0x65700802eb8609c4, 0x3020b556c89387da, 0x0001f03440378769 }, /* a */
  { 0x73ecbcbbc2fe516a, 0x21a88b46019ee078, 0x6f78f8f821cdf972, 0x51902755c97474e1, 0x036fde5f4ca75dcb, 0x81f2aa5e0bce663f, 0x0071956b012817c0, 0x2770dcf7f7185a2b }, /* b */
  { 0x8768059be89e36af, 0x43da42b35757b803, 0x1e0bad88865e21da, 0xafacca5a73236852, 0x10d0ce783e5ebd08, 0x995c0200bae18271, 0x4c082d55b224e1f6, 0x80007c0d100de1da }, /* p */
  { 0x10e955e894409333, 0xa5c29e884d86660d, 0x42d778a51b701611, 0x693b56cc4d41c7fb, 0x95e660d3b641c6d7, 0x73f78460a43b9f66, 0x87fdda647bb639ca, 0x53590545a052051b }, /* r2 */
  { 0x717db632094f9b5b, 0x018ef3923b4255f8, 0xd6115c0919412876, 0x1d1c41e039fb32b9, 0x10d0ce783e5ebd09, 0x995c0200bae18271, 0x4c082d55b224e1f6, 0x80007c0d100de1da }, /* q */
  { 0xb1a195717a8fd5bc, 0x37b778339d769403, 0x0ba7d97bc29b15ab, 0xd42b26c7559affa8, 0x636df8374e2d9569, 0xc68958170104b889, 0xc0435800db018e2c, 0x32573df368d3abbb }, /* r2q */
  {
    { 0x0000000000000003, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* px */
    { 0xe109f64b0d2845b5, 0x2112f42600d5783a, 0xb62b18e2d6d4bcf1, 0x1d69806e0cc5e38c, 0x9fdb7a1e9230f078, 0x870727c3df007d3a, 0x5e7221d67a01b361, 0x3f1f3a51b164ffc0 }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0x8f69d5c0fd131fb1LL, /* n */
  0xd7f54d8866c0e32dLL /* nq */
 };

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_parameters.h */
/* ----------------------------------------------------------------------------------------------- */
