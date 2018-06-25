

#include <stdio.h>
#include <libakrypt.h>

int main( void )
{
    char *str = NULL;

    /* определяем дескриптор и инициализируем его */
    ak_handle handle = ak_error_wrong_handle;

    /* определяем данные для хэширования */
    ak_uint8 data[44] = "The quick brown fox jumps over the lazy dog";
   // ak_uint8 data2[113] ="abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    /* буффер для хранения результата */
    ak_buffer buffer = NULL;
    /* значение, которое должно быть вычислено */
    ak_uint8 lazy[28] =
            {
                    0xd1,0x5d,0xad,0xce,0xaa,0x4d,0x5d,0x7b,0xb3,0xb4,0x8f,0x44,0x64,0x21,0xd5,
                    0x42,0xe0,0x8a,0xd8,0x88,0x73,0x05,0xe2,0x8d,0x58,0x33,0x57,0x95
            };
    ak_uint8 lazy256[32] =
            {
                    0x69,0x07,0x0d,0xda,0x01,0x97,0x5c,0x8c,0x12,0x0c,0x3a,0xad,0xa1,0xb2,0x82,0x39,0x4e,0x7f,0x03,0x2f,
                    0xa9, 0xcf,0x32,0xf4,0xcb,0x22,0x59,0xa0,0x89,0x7d,0xfc,0x04
            };

    ak_uint8 lazy384[48] =
            {
                    0x70,0x63,0x46,0x5e,0x08,0xa9,0x3b,0xce,0x31,0xcd,0x89,0xd2,0xe3,0xca,0x8f,0x60,0x24,0x98,0x69,0x6e,
                    0x25,0x35,0x92,0xed,0x26,0xf0,0x7b,0xf7,0xe7,0x03,0xcf,0x32,0x85,0x81,0xe1,0x47,0x1a,0x7b,0xa7,0xab,
                    0x11,0x9b,0x1a,0x9e,0xbd,0xf8,0xbe,0x41
            };
    ak_uint8 lazy512[64]=
            {
                    0x01,0xde,0xdd,0x5d,0xe4,0xef,0x14,0x64,0x24,0x45,0xba,0x5f,0x5b,0x97,0xc1,0x5e,0x47,0xb9,0xad,0x93,
                    0x13,0x26,0xe4,0xb0,0x72,0x7c,0xd9,0x4c,0xef,0xc4,0x4f,0xff,0x23,0xf0,0x7b,0xf5,0x43,0x13,0x99,0x39,
                    0xb4,0x91,0x28,0xca,0xf4,0x36,0xdc,0x1b,0xde,0xe5,0x4f,0xcb,0x24,0x02,0x3a,0x08,0xd9,0x40,0x3f,0x9b,
                    0x4b,0xf0,0xd4,0x50
            };
    ak_uint8 lazy128shake[32]=
            {
                    0xf4,0x20,0x2e,0x3c,0x58,0x52,0xf9,0x18,0x2a,0x04,0x30,0xfd,0x81,0x44,0xf0,0xa7,0x4b,0x95,0xe7,0x41,
                    0x7e,0xca,0xe1,0x7d,0xb0,0xf8,0xcf,0xee,0xd0,0xe3,0xe6,0x6e
            };

    /* инициализируем библиотеку */
    if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
        return ak_libakrypt_destroy();

    /* создаем дескриптор функции хеширования sha3-224 */
    if(( handle = ak_hash_new_sha3_224()) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
        return ak_libakrypt_destroy();
    }

    printf("data: %s\n", data );

    /* ожидаемый размер хэш-кода */
    printf("expected code size: %d bytes\n", (int) ak_hash_get_icode_size( handle ));

    /* вычисление хэш-кода */
    if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
        return ak_libakrypt_destroy();
    }

    /* вывод информации о результате вычисления */
    printf("obtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
    printf("hash224: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer ));
    free(str);
    buffer = ak_buffer_delete( buffer );
    handle=ak_handle_delete(handle);

    /* вывод заранее подсчитанной константы */
    printf("hash224: %s (expected)\n\n", str = ak_ptr_to_hexstr( lazy, sizeof( lazy ), ak_false ));
    free(str);

    /* создаем дескриптор функции хеширования sha3-256 */
    if(( handle = ak_hash_new_sha3_256()) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
        return ak_libakrypt_destroy();
    }

    /* ожидаемый размер хэш-кода */
    printf("expected code size: %d bytes\n", (int) ak_hash_get_icode_size( handle ));

    /* вычисление хэш-кода */
    if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
        return ak_libakrypt_destroy();
    }

    /* вывод информации о результате вычисления */
    printf("obtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
    printf("hash256: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer ));
    free(str);
    buffer = ak_buffer_delete( buffer );
    handle=ak_handle_delete(handle);

    /* вывод заранее подсчитанной константы */
    printf("hash256: %s (expected)\n\n", str = ak_ptr_to_hexstr( lazy256, sizeof( lazy256 ), ak_false ));
    free(str);

    /* создаем дескриптор функции хеширования sha3-384 */
    if(( handle = ak_hash_new_sha3_384()) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
        return ak_libakrypt_destroy();
    }

    /* ожидаемый размер хэш-кода */
    printf("expected code size: %d bytes\n", (int) ak_hash_get_icode_size( handle ));

    /* вычисление хэш-кода */
    if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
        return ak_libakrypt_destroy();
    }

    /* вывод информации о результате вычисления */
    printf("obtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
    printf("hash384: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer ));
    free(str);
    buffer = ak_buffer_delete( buffer );
    handle=ak_handle_delete(handle);

    /* вывод заранее подсчитанной константы */
    printf("hash384: %s (expected)\n\n", str = ak_ptr_to_hexstr( lazy384, sizeof( lazy384 ), ak_false ));
    free(str);

    /* создаем дескриптор функции хеширования sha3-512 */
    if(( handle= ak_hash_new_sha3_512()) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
        return ak_libakrypt_destroy();
    }

    /* ожидаемый размер хэш-кода */
    printf("expected code size: %d bytes\n", (int) ak_hash_get_icode_size( handle ));

    /* вычисление хэш-кода */
    if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
        return ak_libakrypt_destroy();
    }

    /* вывод информации о результате вычисления */
    printf("obtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
    printf("hash512: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer ));
    free(str);
    buffer = ak_buffer_delete( buffer );
    handle=ak_handle_delete(handle);

    /* вывод заранее подсчитанной константы */
    printf("hash512: %s (expected)\n\n", str = ak_ptr_to_hexstr( lazy512, sizeof( lazy512 ), ak_false ));
    free(str);

    /* создаем дескриптор функции хеширования shake128 */
    if(( handle= ak_hash_new_shake128()) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
        return ak_libakrypt_destroy();
    }

    /* ожидаемый размер хэш-кода */
    printf("expected code size: %d bytes\n", (int) ak_hash_get_icode_size( handle ));

    /* вычисление хэш-кода */
    if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
        return ak_libakrypt_destroy();
    }

    /* вывод информации о результате вычисления */
    printf("obtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
    printf("hash_shake128: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer ));
    free(str);
    buffer = ak_buffer_delete( buffer );
    handle=ak_handle_delete(handle);

    /* вывод заранее подсчитанной константы */
    printf("hash_shake128: %s (expected)\n\n", str = ak_ptr_to_hexstr( lazy128shake, sizeof( lazy128shake ), ak_false ));
    free(str);

    return ak_libakrypt_destroy(); /* останавливаем библиотеку и выходим */
}
