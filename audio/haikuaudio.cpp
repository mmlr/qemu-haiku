/*
 * QEMU Haiku audio output driver
 * 
 * Copyright (c) 2005-2009 Michael Lotz
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

extern "C" {
#include "qemu-common.h"
#include "audio/audio.h"
#define AUDIO_CAP "haiku"
#include "audio_int.h"

static	int		haiku_run_out(HWVoiceOut *hw);
static	int		haiku_write(SWVoiceOut *sw, void *buf, int len);
static	int		haiku_init_out(HWVoiceOut *hw, struct audsettings *as);
static	void	haiku_fini_out(HWVoiceOut *hw);
static	int		haiku_ctl_out(HWVoiceOut *hw, int cmd, ...);

static	int		haiku_init_in(HWVoiceIn *hw, struct audsettings *as);
static	void	haiku_fini_in(HWVoiceIn *hw);
static	int		haiku_run_in(HWVoiceIn *hw);
static	int		haiku_read(SWVoiceIn *sw, void *buf, int size);
static	int		haiku_ctl_in(HWVoiceIn *hw, int cmd, ...);

static	void *	haiku_audio_init(void);
static	void	haiku_audio_fini(void *opaque);
}

// name conflict
#define load_image _b_load_image
#include <SoundPlayer.h>

typedef struct BufferInfo {
	uint8 *buffer;
	uint32 size;
	uint32 read_position;
	uint32 write_position;
	uint32 valid;
} BufferInfo;

typedef struct HaikuVoiceOut {
	HWVoiceOut hw;
	BufferInfo *buffer;
	BSoundPlayer *player;
} HaikuVoiceOut;


typedef struct HaikuVoiceIn {
	HWVoiceIn hw;
	BufferInfo *buffer;
} HaikuVoiceIn;


void
PlayBuffer(void *cookie, void *buffer, size_t size, const media_raw_audio_format &format)
{
	BufferInfo *info = (BufferInfo *)cookie;
	if (info->valid == 0) {
		memset(buffer, 0, size);
		return;
	}

	uint32 max = 0;
	uint32 location = 0;
	bool wrapped = (info->read_position + info->valid) > info->size;
	if (wrapped) {
		max = MIN(MIN(info->size - info->read_position, info->valid), size);
		memcpy(buffer, info->buffer + info->read_position, max);
		info->read_position = (info->read_position + max) % info->size;
		info->valid -= max;
		location += max;

		if (max >= size)
			return;
	}

	max = MIN(info->valid, size - location);
	memcpy((uint8 *)buffer + location, info->buffer + info->read_position, max);
	info->read_position = (info->read_position + max) % info->size;
	info->valid -= max;
	location += max;

	if (location < size)
		memset((uint8 *)buffer + location, 0, size - location);
}


static int
haiku_run_out(HWVoiceOut *hw)
{
	HaikuVoiceOut *voice = (HaikuVoiceOut *)hw;
	BufferInfo *info = voice->buffer;
	if (!info)
		return 0;

	int live = audio_pcm_hw_get_live_out(hw);
	if (live <= 0)
		return 0;

	int position = hw->rpos;
	int available = hw->samples - position;
	int bufferAvailable = MIN(info->size - info->valid, info->size - info->write_position);
	int samples = MIN(MIN(live, available), bufferAvailable >> hw->info.shift);

	if (samples > 0) {
		struct st_sample *src = hw->mix_buf + position;
		uint8 *dst = (uint8 *)advance(info->buffer, info->write_position);
		hw->clip(dst, src, samples);
		mixeng_clear(src, samples);
		hw->rpos = (position + samples) % hw->samples;
		info->write_position += samples << hw->info.shift;
		info->write_position %= info->size;
		info->valid += samples << hw->info.shift;
	}

	return samples;
}


static int
haiku_write(SWVoiceOut *sw, void *buf, int len)
{
	return audio_pcm_sw_write(sw, buf, len);
}


static int
haiku_init_out(HWVoiceOut *hw, struct audsettings *as)
{
	media_raw_audio_format format;
	format.frame_rate = as->freq;
	format.channel_count = as->nchannels;
	format.byte_order = B_MEDIA_LITTLE_ENDIAN;
	format.buffer_size = 2048;

	switch (as->fmt) {
		case AUD_FMT_U8:
			format.format = media_raw_audio_format::B_AUDIO_UCHAR;
			break;
		case AUD_FMT_S8:
			format.format = media_raw_audio_format::B_AUDIO_CHAR;
			break;
		case AUD_FMT_S16:
			format.format = media_raw_audio_format::B_AUDIO_SHORT;
			break;
		case AUD_FMT_U16:
			printf("Audio Format not supported!\n");
			return 1;
	}

	audio_pcm_init_info(&hw->info, as);
	hw->samples = (format.buffer_size * 10) >> hw->info.shift;
	hw->rpos = 0;

	BufferInfo *info = new BufferInfo;
	//info->size = hw->samples * (format.format & 0x0f) * format.channel_count;
	info->size = (hw->samples << hw->info.shift) * 4;
	info->buffer = (uint8 *)qemu_malloc(info->size);
	info->read_position = 0;
	info->write_position = 0;
	info->valid = 0;

	HaikuVoiceOut *voice = (HaikuVoiceOut *)hw;
	voice->buffer = info;
	voice->player = new BSoundPlayer(&format, "QEMU", PlayBuffer, NULL, info);
	voice->player->Start();
	voice->player->SetHasData(true);
	return 0;
}


static void
haiku_fini_out(HWVoiceOut *hw)
{
	HaikuVoiceOut *voice = (HaikuVoiceOut *)hw;

	voice->player->Stop();
	voice->player = NULL;

	free(voice->buffer->buffer);
	delete voice->buffer;
	voice->buffer = NULL;

	delete voice->player;
}


static int
haiku_ctl_out(HWVoiceOut *hw, int cmd, ...)
{
	HaikuVoiceOut *voice = (HaikuVoiceOut *)hw;
	if (!voice->player)
		return 0;

	switch (cmd) {
		case VOICE_ENABLE:
			voice->player->SetHasData(true);
			break;

		case VOICE_DISABLE:
			//voice->player->SetHasData(false);
			break;
	}

	return 0;
}


static int
haiku_init_in(HWVoiceIn *hw, struct audsettings *as)
{
	audio_pcm_init_info(&hw->info, as);
	hw->samples = 1024;
	return 0;
}


static void
haiku_fini_in(HWVoiceIn *hw)
{
}


static int
haiku_run_in(HWVoiceIn *hw)
{
	return 0;
}


static int
haiku_read(SWVoiceIn *sw, void *buf, int size)
{
	return 0;
}


static int
haiku_ctl_in(HWVoiceIn *hw, int cmd, ...)
{
	return 0;
}


static void *
haiku_audio_init(void)
{
	// just an opaque handle, doesn't matter, we don't use it
	return (void *)&haiku_audio_init;
}


static void
haiku_audio_fini(void *opaque)
{
}


struct audio_pcm_ops haiku_pcm_ops = {
	haiku_init_out,
	haiku_fini_out,
	haiku_run_out,
	haiku_write,
	haiku_ctl_out,

	haiku_init_in,
	haiku_fini_in,
	haiku_run_in,
	haiku_read,
	haiku_ctl_in
};


struct audio_driver haiku_audio_driver = {
	"haiku",
	"Haiku Native Audio",
	NULL,
	haiku_audio_init,
	haiku_audio_fini,
	&haiku_pcm_ops,
	1,
	1,
	1,
	sizeof(HaikuVoiceOut),
	sizeof(HaikuVoiceIn)
};
