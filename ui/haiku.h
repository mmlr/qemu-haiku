/*
 * QEMU Haiku display driver
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

#ifndef _HAIKU_H_
#define _HAIKU_H_

#include <Accelerant.h>
#include <Application.h>
#include <Bitmap.h>
#include <MessageFilter.h>
#include <MessageQueue.h>
#include <View.h>
#include <Window.h>

class QEMUWindow;
class QEMUView;

class QEMUApplication : public BApplication {
public:
							QEMUApplication(int argc, char **argv);

virtual	bool				QuitRequested();
		void				InitDisplay();

private:
static	int32				RunQEMUMain(void *arg);

		int					fArgC;
		char **				fArgV;

		thread_id			fThread;
		QEMUWindow *		fWindow;
};


class QEMUWindow : public BWindow {
public:
							QEMUWindow();

virtual	void				MessageReceived(BMessage *message);

private:
		QEMUView *			fView;
};


class QEMUView : public BView {
public:
							QEMUView(BRect frame);
virtual						~QEMUView();

virtual	void				AttachedToWindow();

		void				Update(BPoint point, int width, int height);
virtual	void				Draw(BRect updateRect);

		void				UpdateFrameBuffer(int width, int height,
								uchar *bits, int bytesPerRow,
								int bitsPerPixel);

static	void				UpdateFullScreen();
static	void				CenterMouse(bool &warp);
static	void				StartGrab(bool &grab);
static	void				EndGrab(bool &grab, int32 modifiers);

static	void				QueueKeycode(uint8 keycode);
static	void				QueueKeysym(int32 keysym);
static	void				QueueMouseEvent(BPoint where, int32 deltaZ,
								int32 buttonState);
static	void				QueueShutdownRequest();
static	void				QueueConsoleSelect(uint8 console);
static	void				QueueInvalidation();

		void				ProcessEvents();

private:
		void				QueueEvent(BMessage *event);

static	filter_result		MessageFilter(BMessage *message, BHandler **target,
								BMessageFilter *filter);

		BBitmap *			fBitmap;
		BPoint				fWindowLocation;
		display_mode		fDisplayMode;

		uint8 *				fFrameBuffer;
		uint32				fFrameBufferSize;
		uint32				fBytesPerRow;
		color_space			fColorSpace;

		BMessageQueue		fEventQueue;
};

#endif
