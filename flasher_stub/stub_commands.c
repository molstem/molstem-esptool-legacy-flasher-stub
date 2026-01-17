/*
 * SPDX-FileCopyrightText: 2019-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdlib.h>
#include <string.h>
#include "stub_commands.h"

/*
 * SHA256 implementation for stub flasher
 * ESP32-C3 uses hardware accelerator via ROM functions
 * Other chips use software implementation
 */
#ifndef ESP32C3
/* Software SHA256 implementation for non-ESP32C3 chips */
typedef struct {
    uint32_t state[8];
    uint32_t count[2];
    uint8_t buffer[64];
} SHA256_CTX_SW;

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SHA256_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTR(x, 2) ^ SHA256_ROTR(x, 13) ^ SHA256_ROTR(x, 22))
#define SHA256_EP1(x) (SHA256_ROTR(x, 6) ^ SHA256_ROTR(x, 11) ^ SHA256_ROTR(x, 25))
#define SHA256_SIG0(x) (SHA256_ROTR(x, 7) ^ SHA256_ROTR(x, 18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ ((x) >> 10))

static void sha256_transform(SHA256_CTX_SW *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    int i;

    for (i = 0; i < 16; i++) {
        m[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) | ((uint32_t)data[i * 4 + 3]);
    }
    for (; i < 64; i++) {
        m[i] = SHA256_SIG1(m[i - 2]) + m[i - 7] + SHA256_SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + SHA256_EP1(e) + SHA256_CH(e, f, g) + sha256_k[i] + m[i];
        t2 = SHA256_EP0(a) + SHA256_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX_SW *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX_SW *ctx, const uint8_t *data, uint32_t len) {
    uint32_t i, j;
    j = (ctx->count[0] >> 3) & 63;
    if ((ctx->count[0] += len << 3) < (len << 3)) ctx->count[1]++;
    ctx->count[1] += (len >> 29);

    if ((j + len) > 63) {
        i = 64 - j;
        memcpy(&ctx->buffer[j], data, i);
        sha256_transform(ctx, ctx->buffer);
        for (; i + 63 < len; i += 64) {
            sha256_transform(ctx, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&ctx->buffer[j], &data[i], len - i);
}

static void sha256_final(SHA256_CTX_SW *ctx, uint8_t digest[32]) {
    uint8_t finalcount[8];
    uint32_t i;

    for (i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((ctx->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    }

    sha256_update(ctx, (uint8_t *)"\x80", 1);
    while ((ctx->count[0] & 504) != 448) {
        sha256_update(ctx, (uint8_t *)"\0", 1);
    }
    sha256_update(ctx, finalcount, 8);

    for (i = 0; i < 32; i++) {
        digest[i] = (uint8_t)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
}
#endif /* !ESP32C3 */
#include "stub_write_flash.h"
#include "stub_flasher.h"
#include "rom_functions.h"
#include "slip.h"
#include "soc_support.h"
#include "stub_io.h"

#if (ESP32S3 && !ESP32S3BETA2) || ESP32P4 || ESP32P4RC1 || ESP32C5
static esp_rom_spiflash_result_t SPIRead4B(int spi_num, uint32_t flash_addr, uint8_t* buf, int len)
{
    uint8_t cmd_len = 8;

    esp_rom_spiflash_wait_idle();
    while (len > 0) {
        int rd_length;
        if (len > 16 ) {    //16 = read_sub_len
            rd_length = 16;
        } else {
            rd_length = len;
        }
        esp_rom_opiflash_exec_cmd(spi_num, SPI_FLASH_FASTRD_MODE,
                                CMD_FSTRD4B, cmd_len,
                                flash_addr, 32,
                                8,
                                NULL, 0,
                                buf, 8 * rd_length,
                                ESP_ROM_OPIFLASH_SEL_CS0,
                                false);

        len -= rd_length;
        buf += rd_length;
        flash_addr += rd_length;
    }
    return ESP_ROM_SPIFLASH_RESULT_OK;
}
#endif // ESP32S3 || ESP32P4 || ESP32P4RC1 || ESP32C5

int handle_flash_erase(uint32_t addr, uint32_t len) {
  if (addr % FLASH_SECTOR_SIZE != 0) return 0x32;
  if (len % FLASH_SECTOR_SIZE != 0) return 0x33;
  if (SPIUnlock() != 0) return 0x34;

  while (len > 0 && (addr % FLASH_BLOCK_SIZE != 0)) {
    #if defined(ESP32S3) && !defined(ESP32S3BETA2)
        if (large_flash_mode) {
          if (esp_rom_opiflash_erase_sector(addr / FLASH_SECTOR_SIZE) != 0) return 0x35;
        } else {
          if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x35;
        }
    #elif ESP32P4 || ESP32P4RC1 || ESP32C5
        if (large_flash_mode) {
          spi_write_enable();
          esp_rom_spiflash_wait_idle();
          esp_rom_opiflash_exec_cmd(1, SPI_FLASH_SLOWRD_MODE,
            CMD_SECTOR_ERASE_4B, 8,
            addr, 32,
            0,
            NULL, 0,
            NULL, 0,
            1,
            true);
        } else {
          if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x35;
        }
    #else
      if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x35;
    #endif // ESP32S3
    len -= FLASH_SECTOR_SIZE;
    addr += FLASH_SECTOR_SIZE;
  }

  while (len > FLASH_BLOCK_SIZE) {
    #if defined(ESP32S3) && !defined(ESP32S3BETA2)
      if (large_flash_mode) {
        if (esp_rom_opiflash_erase_block_64k(addr / FLASH_BLOCK_SIZE) != 0) return 0x36;
      } else {
        if (SPIEraseBlock(addr / FLASH_BLOCK_SIZE) != 0) return 0x36;
      }
    #elif ESP32P4 || ESP32P4RC1 || ESP32C5
      if (large_flash_mode) {
        spi_write_enable();
        esp_rom_spiflash_wait_idle();
        esp_rom_opiflash_exec_cmd(1, SPI_FLASH_SLOWRD_MODE,
          CMD_LARGE_BLOCK_ERASE_4B, 8,
          addr, 32,
          0,
          NULL, 0,
          NULL, 0,
          1,
          true);
    } else {
      if (SPIEraseBlock(addr / FLASH_BLOCK_SIZE) != 0) return 0x36;
    }
    #else
      if (SPIEraseBlock(addr / FLASH_BLOCK_SIZE) != 0) return 0x36;
    #endif // ESP32S3
    len -= FLASH_BLOCK_SIZE;
    addr += FLASH_BLOCK_SIZE;
  }

  while (len > 0) {
    #if defined(ESP32S3) && !defined(ESP32S3BETA2)
      if (large_flash_mode) {
        if (esp_rom_opiflash_erase_sector(addr / FLASH_SECTOR_SIZE) != 0) return 0x37;
      } else {
        if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x37;
      }
    #elif ESP32P4 || ESP32P4RC1 || ESP32C5
      if (large_flash_mode) {
        spi_write_enable();
        esp_rom_spiflash_wait_idle();
        esp_rom_opiflash_exec_cmd(1, SPI_FLASH_SLOWRD_MODE,
          CMD_SECTOR_ERASE_4B, 8,
          addr, 32,
          0,
          NULL, 0,
          NULL, 0,
          1,
          true);
      } else {
        if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x35;
      }
    #else
      if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x37;
    #endif // ESP32S3
    len -= FLASH_SECTOR_SIZE;
    addr += FLASH_SECTOR_SIZE;
  }

  return 0;
}

void handle_flash_read(uint32_t addr, uint32_t len, uint32_t block_size,
                  uint32_t max_in_flight) {
  uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[16];
  struct MD5Context ctx;
  uint32_t num_sent = 0, num_acked = 0;
  uint8_t res = 0;

  /* This is one routine where we still do synchronous I/O */
  stub_rx_async_enable(false);

  if (block_size > sizeof(buf)) {
    return;
  }
  MD5Init(&ctx);
  while (num_acked < len && num_acked <= num_sent) {
    while (num_sent < len && num_sent - num_acked < max_in_flight) {
      uint32_t n = len - num_sent;
      if (n > block_size) n = block_size;
      #if (ESP32S3 && !ESP32S3BETA2) || ESP32P4 || ESP32P4RC1 || ESP32C5
        if (large_flash_mode) {
          res = SPIRead4B(1, addr, buf, n);
        } else {
          res = SPIRead(addr, (uint32_t *)buf, n);
        }
      #else
        res = SPIRead(addr, (uint32_t *)buf, n);
      #endif // ESP32S3
      if (res != 0) {
        break;
      }
      SLIP_send(buf, n);
      MD5Update(&ctx, buf, n);
      addr += n;
      num_sent += n;
    }
    int r = SLIP_recv(&num_acked, sizeof(num_acked));
    if (r != 4) {
      break;
    }
  }
  MD5Final(digest, &ctx);
  SLIP_send(digest, sizeof(digest));

  /* Go back to async RX */
  stub_rx_async_enable(true);
}

int handle_flash_get_md5sum(uint32_t addr, uint32_t len) {
  uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[16];
  uint8_t res = 0;
  struct MD5Context ctx;
  MD5Init(&ctx);
  while (len > 0) {
    uint32_t n = len;
    if (n > FLASH_SECTOR_SIZE) {
      n = FLASH_SECTOR_SIZE;
    }
    #if (ESP32S3 && !ESP32S3BETA2) || ESP32P4 || ESP32P4RC1 || ESP32C5
      if (large_flash_mode) {
        res = SPIRead4B(1, addr, buf, n);
      } else {
        res = SPIRead(addr, (uint32_t *)buf, n);
      }
    #else
      res = SPIRead(addr, (uint32_t *)buf, n);
    #endif // ESP32S3
    if (res != 0) {
      return 0x63;
    }
    MD5Update(&ctx, buf, n);
    addr += n;
    len -= n;
  }
  MD5Final(digest, &ctx);
  /* ESP32 ROM sends as hex, but we just send raw bytes - esptool.py can handle either. */
  SLIP_send_frame_data_buf(digest, sizeof(digest));
  return 0;
}

int handle_flash_get_sha256sum(uint32_t addr, uint32_t len) {
  /* Use static buffers to avoid stack overflow in stub's limited memory */
  static uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[32];
  uint8_t res = 0;

#ifdef ESP32C3
  /* Use hardware SHA256 accelerator via ROM functions */
  static SHA_CTX ctx;

  /* Zero-initialize the context - ROM may expect this */
  memset(&ctx, 0, sizeof(ctx));

  ets_sha_enable();
  ets_sha_init(&ctx, SHA2_256);
  ets_sha_starts(&ctx, 0);  /* 0 for non-SHA512/t variants */
  while (len > 0) {
    uint32_t n = len;
    if (n > FLASH_SECTOR_SIZE) {
      n = FLASH_SECTOR_SIZE;
    }
    res = SPIRead(addr, (uint32_t *)buf, n);
    if (res != 0) {
      ets_sha_disable();
      return 0x63;
    }
    ets_sha_update(&ctx, buf, n, true);  /* update_ctx = true */
    addr += n;
    len -= n;
  }
  ets_sha_finish(&ctx, digest);
  ets_sha_disable();
#else
  /* Use software SHA256 implementation */
  SHA256_CTX_SW ctx;
  sha256_init(&ctx);
  while (len > 0) {
    uint32_t n = len;
    if (n > FLASH_SECTOR_SIZE) {
      n = FLASH_SECTOR_SIZE;
    }
    #if (ESP32S3 && !ESP32S3BETA2) || ESP32P4 || ESP32P4RC1 || ESP32C5
      if (large_flash_mode) {
        res = SPIRead4B(1, addr, buf, n);
      } else {
        res = SPIRead(addr, (uint32_t *)buf, n);
      }
    #else
      res = SPIRead(addr, (uint32_t *)buf, n);
    #endif // ESP32S3
    if (res != 0) {
      return 0x63;
    }
    sha256_update(&ctx, buf, n);
    addr += n;
    len -= n;
  }
  sha256_final(&ctx, digest);
#endif /* ESP32C3 */

  /* Send raw 32 bytes */
  SLIP_send_frame_data_buf(digest, sizeof(digest));
  return 0;
}

esp_command_error handle_spi_set_params(uint32_t *args, int *status)
{
  *status = SPIParamCfg(args[0], args[1], args[2], args[3], args[4], args[5]);
  return *status ? ESP_FAILED_SPI_OP : ESP_OK;
}

esp_command_error handle_spi_attach(uint32_t hspi_config_arg)
{
#ifdef ESP8266
        /* ESP8266 doesn't yet support SPI flash on HSPI, but could:
         see https://github.com/themadinventor/esptool/issues/98 */
        SelectSpiFunction();
#else
        /* Stub calls spi_flash_attach automatically when it boots,
          therefore, we need to "unattach" the flash before attaching again
          with different configuration to avoid issues. */

        // Configure the SPI flash pins back as classic GPIOs
        PIN_FUNC_SELECT(PERIPHS_IO_MUX_SPICLK_U, FUNC_GPIO);
        PIN_FUNC_SELECT(PERIPHS_IO_MUX_SPIQ_U, FUNC_GPIO);
        PIN_FUNC_SELECT(PERIPHS_IO_MUX_SPID_U, FUNC_GPIO);
        PIN_FUNC_SELECT(PERIPHS_IO_MUX_SPICS0_U, FUNC_GPIO);

        /* spi_flash_attach calls SelectSpiFunction() and another
           function to initialise SPI flash interface.

           Second argument 'legacy' mode is not currently supported.
        */
        spi_flash_attach(hspi_config_arg, 0);
#endif
        return ESP_OK; /* neither function/attach command takes an arg */
}

static uint32_t *mem_offset;
static uint32_t mem_remaining;

esp_command_error handle_mem_begin(uint32_t size, uint32_t offset)
{
    mem_offset = (uint32_t *)offset;
    mem_remaining = size;
    return ESP_OK;
}

esp_command_error handle_mem_data(void *data, uint32_t length)
{
    uint32_t *data_words = (uint32_t *)data;
    if (mem_offset == NULL && length > 0) {
        return ESP_NOT_IN_FLASH_MODE;
    }
    if (length > mem_remaining) {
        return ESP_TOO_MUCH_DATA;
    }
    if (length % 4 != 0) {
        return ESP_BAD_DATA_LEN;
    }

    for(int i = 0; i < length; i+= 4) {
        *mem_offset++ = *data_words++;
        mem_remaining -= 4;
    }
    return ESP_OK;
}

esp_command_error handle_mem_finish()
{
    esp_command_error res = mem_remaining > 0 ? ESP_NOT_ENOUGH_DATA : ESP_OK;
    mem_remaining = 0;
    mem_offset = NULL;
    return res;
}

esp_command_error handle_write_reg(const write_reg_args_t *cmds, uint32_t num_commands)
{
    for (uint32_t i = 0; i < num_commands; i++) {
        const write_reg_args_t *cmd = &cmds[i];
        ets_delay_us(cmd->delay_us);
        uint32_t v = cmd->value & cmd->mask;
        if (cmd->mask != UINT32_MAX) {
            v |= READ_REG(cmd->addr) & ~cmd->mask;
        }
        WRITE_REG(cmd->addr, v);
    }
    return ESP_OK;
}

#if ESP32S2_OR_LATER
esp_command_error handle_get_security_info()
{
  uint8_t buf[SECURITY_INFO_BYTES];
  esp_command_error ret;

  #ifdef ESP32C3
  if (_rom_eco_version >= 7)
    ret = GetSecurityInfoProcNewEco(NULL, NULL, buf);
  else
    ret = GetSecurityInfoProc(NULL, NULL, buf);
  #else
  ret = GetSecurityInfoProc(NULL, NULL, buf);
  #endif // ESP32C3
  if (ret == ESP_OK)
    SLIP_send_frame_data_buf(buf, sizeof(buf));
  return ret;
}
#endif // ESP32S2_OR_LATER
