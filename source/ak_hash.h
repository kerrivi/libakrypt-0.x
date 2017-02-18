/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                     */
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
/*  ak_hash.h                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
#ifndef __AK_HASH_H__
#define __AK_HASH_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_tools.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Тип данных, определяющий набор перестановок, используемых в ГОСТ 28147-89 и ГОСТ Р 34.11-94.   */
 typedef ak_uint8 kbox[8][16];
 typedef kbox *ak_kbox;

/*! Тип данных, реализующий перестановки на множестве из 8 бит */
 typedef ak_uint8 sbox[256];
 typedef sbox *ak_sbox;

/* ----------------------------------------------------------------------------------------------- */
 int ak_kbox_to_sbox( const ak_kbox k, sbox k21, sbox k43, sbox k65, sbox k87 );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief функция создания контекста хеширования */
 typedef ak_hash ( ak_function_hash )( void );
/*! \brief функция очистки контекста хеширования */
 typedef void ( ak_function_hash_clean )( ak_pointer );
/*! \brief итерационная функция хеширования */
 typedef void ( ak_function_hash_update )( ak_pointer, const ak_pointer , const size_t );
/*! \brief функция завершения вычислений и получения конечного результата */
 typedef ak_buffer ( ak_function_hash_finalize ) ( ak_pointer,
                                                      const ak_pointer , const size_t, ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий контекст алгоритима хеширования                                      */
 struct hash {
  /*! \brief размер обрабатываемого блока входных данных */
   size_t bsize;
  /*! \brief размер выходного блока (хеш-кода) */
   size_t hsize;
  /*! \brief указатель на внутренние данные контекста */
   ak_pointer data;
  /*! \brief OID алгоритма хеширования */
   ak_oid oid;
  /*! \brief функция очистки контекста */
   ak_function_hash_clean *clean;
  /*! \brief функция обновления состояния контекста */
   ak_function_hash_update *update;
  /*! \brief функция завершения вычислений и получения конечного результата */
   ak_function_hash_finalize *finalize;
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание нового контекста хеширования */
 ak_hash ak_hash_new( const size_t , const size_t );
/*! \brief Проверка корректной работы функции хеширования Стрибог-256 */
 ak_bool ak_hash_test_streebog256( void );
/*! \brief Проверка корректной работы функции хеширования Стрибог-512 */
 ak_bool ak_hash_test_streebog512( void );
/*! \brief Проверка корректной работы функции хеширования ГОСТ Р 34.11-94 */
 ak_bool ak_hash_test_gosthash94( void );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hash.h  */
/* ----------------------------------------------------------------------------------------------- */
