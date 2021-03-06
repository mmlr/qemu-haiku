/*
 * QEMU Haiku display driver
 * 
 * Copyright (c) 2005-2013 Michael Lotz
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

#include "haiku.h"

#include <Cursor.h>
#include <Path.h>
#include <Screen.h>
#include <WindowScreen.h>

#include <stdio.h>
#include <stdlib.h>

#include <signal.h>

struct QemuConsole;

static QEMUApplication *sApplication = NULL;
static QEMUWindow *sWindow = NULL;
static QEMUView *sView = NULL;
static bool sFullScreen = false;
static QemuConsole *sCurrentConsole = NULL;
static bool sGraphicConsole = false;
static bool sAbsoluteMouse = false;
static bool sGrabInput = false;
static int sWidth = 100;
static int sHeight = 100;
static BPoint sCenter;
static BPoint sPreviousLocation;
static thread_id sMainThread = -1;

static const uint32 kMessageBlockSignals = 'bksg';

static const uint32 kKeycodeEvent = 'keyc';
static const uint32 kKeysymEvent = 'keys';
static const uint32 kMouseEvent = 'mous';
static const uint32 kConsoleSelectEvent = 'cons';
static const uint32 kShutdownRequest = 'shut';
static const uint32 kInvalidationRequest = 'ival';


// QEMU C interface
extern "C" {
#define new			_new
#define class		_class
#define typename	_typename
	// Guard against reserved keywords in C includes

#include "qemu-common.h"
#include "ui/console.h"
#include "ui/input.h"

#undef new
#undef class
#undef typename

static	void	haiku_update(DisplayChangeListener *dcl, int x, int y, int w,
					int h);
static	void	haiku_switch(DisplayChangeListener *dcl,
					DisplaySurface *newSurface);
static	void	haiku_refresh(DisplayChangeListener *dcl);

		// Redirected QEMU main
		int		qemu_main(int argc, char **argv, char **envp);

		void	qemu_system_shutdown_request(void);
};


// Haiku keycode to scancode table
static const uint8
haiku_to_pc_key[] = {
	0x00,	/* 0x00 */						0x01,	/* 0x01 Esc */
	0x3b,	/* 0x02 F1 */					0x3c,	/* 0x03 F2 */
	0x3d,	/* 0x04 F3 */					0x3e,	/* 0x05 F4 */
	0x3f,	/* 0x06 F5 */					0x40,	/* 0x07 F6 */
	0x41,	/* 0x08 F7 */					0x42,	/* 0x09 F8 */
	0x43,	/* 0x0a F9 */					0x44,	/* 0x0b F10 */
	0x57,	/* 0x0c F11 */					0x58,	/* 0x0d F12 */
	0xb7,	/* 0x0e Print Screen */			0x46,	/* 0x0f Scroll Lock */
	0xc5,	/* 0x10 Pause */				0x29,	/* 0x11 Grave */
	0x02,	/* 0x12 1 */					0x03,	/* 0x13 2 */
	0x04,	/* 0x14 3 */					0x05,	/* 0x15 4 */
	0x06,	/* 0x16 5 */					0x07,	/* 0x17 6 */
	0x08,	/* 0x18 7 */					0x09,	/* 0x19 8 */
	0x0a,	/* 0x1a 9 */					0x0b,	/* 0x1b 0 */
	0x0c,	/* 0x1c Minus */				0x0d,	/* 0x1d Equals */
	0x0e,	/* 0x1e Backspace */			0xd2,	/* 0x1f Insert */
	0xc7,	/* 0x20 Home */					0xc9,	/* 0x21 Page Up */
	0x45,	/* 0x22 Num Lock */				0xb5,	/* 0x23 KP Divide */
	0x37,	/* 0x24 KP Multiply */			0x4a,	/* 0x25 KP Subtract */
	0x0f,	/* 0x26 Tab */					0x10,	/* 0x27 Q */
	0x11,	/* 0x28 W */					0x12,	/* 0x29 E */
	0x13,	/* 0x2a R */					0x14,	/* 0x2b T */
	0x15,	/* 0x2c Y */					0x16,	/* 0x2d U */
	0x17,	/* 0x2e I */					0x18,	/* 0x2f O */
	0x19,	/* 0x30 P */					0x1a,	/* 0x31 Left Bracket */
	0x1b,	/* 0x32 Right Bracket */		0x2b,	/* 0x33 Backslash */
	0xd3,	/* 0x34 Delete */				0xcf,	/* 0x35 End */
	0xd1,	/* 0x36 Page Down */			0x47,	/* 0x37 KP 7 */
	0x48,	/* 0x38 KP 8 */					0x49,	/* 0x39 KP 9 */
	0x4e,	/* 0x3a KP Add */				0x3a,	/* 0x3b Caps Lock */
	0x1e,	/* 0x3c A */					0x1f,	/* 0x3d S */
	0x20,	/* 0x3e D */					0x21,	/* 0x3f F */
	0x22,	/* 0x40 G */					0x23,	/* 0x41 H */
	0x24,	/* 0x42 J */					0x25,	/* 0x43 K */
	0x26,	/* 0x44 L */					0x27,	/* 0x45 Semicolon */
	0x28,	/* 0x46 Single Quote */			0x1c,	/* 0x47 Enter */
	0x4b,	/* 0x48 KP 4 */					0x4c,	/* 0x49 KP 5 */
	0x4d,	/* 0x4a KP 6 */					0x2a,	/* 0x4b Left Shift */
	0x2c,	/* 0x4c Z */					0x2d,	/* 0x4d X */
	0x2e,	/* 0x4e C */					0x2f,	/* 0x4f V */
	0x30,	/* 0x50 B */					0x31,	/* 0x51 N */
	0x32,	/* 0x52 M */					0x33,	/* 0x53 Comma */
	0x34,	/* 0x54 Period */				0x35,	/* 0x55 Slash */
	0x36,	/* 0x56 Right Shift */			0xc8,	/* 0x57 Up */
	0x4f,	/* 0x58 KP 1 */					0x50,	/* 0x59 KP 2 */
	0x51,	/* 0x5a KP 3 */					0x9c,	/* 0x5b KP Enter */
	0x1d,	/* 0x5c Left Control */			0x38,	/* 0x5d Left Alt */
	0x39,	/* 0x5e Space */				0xb8,	/* 0x5f Right Alt */
	0x9d,	/* 0x60 Right Control */		0xcb,	/* 0x61 Left */
	0xd0,	/* 0x62 Down */					0xcd,	/* 0x63 Right */
	0x52,	/* 0x64 KP 0 */					0x53,	/* 0x65 KP . */
	0xdb,	/* 0x66 Left Windows */			0xdc,	/* 0x67 Right Windows */
	0xdd,	/* 0x68 Menu */					0x56,	/* 0x69 */
	0x7d,	/* 0x6a Macron */				0x73,	/* 0x6b Backslash */
	0x7b,	/* 0x6c Muhenkan */				0x79,	/* 0x6d Henkan */
	0x70,	/* 0x6e Hiragana Katakana */	0x00,	/* 0x6f */
	0x00,	/* 0x70 */						0x00,	/* 0x71 */
	0x00,	/* 0x72 */						0x00,	/* 0x73 */
	0x00,	/* 0x74 */						0x00,	/* 0x75 */
	0x00,	/* 0x76 */						0x00,	/* 0x77 */
	0x00,	/* 0x78 */						0x00,	/* 0x79 */
	0x00,	/* 0x7a */						0x00,	/* 0x7b */
	0x00,	/* 0x7c */						0x00,	/* 0x7d */
	0x54,	/* 0x7e Alt SysRq */			0xc6,	/* 0x7f Control Break */	
};


// Key constants from vl.h
#define QEMU_KEY_ESC1(c) ((c) | 0xe100)
#define QEMU_KEY_BACKSPACE	0x007f
#define QEMU_KEY_UP			QEMU_KEY_ESC1('A')
#define QEMU_KEY_DOWN		QEMU_KEY_ESC1('B')
#define QEMU_KEY_RIGHT		QEMU_KEY_ESC1('C')
#define QEMU_KEY_LEFT		QEMU_KEY_ESC1('D')
#define QEMU_KEY_HOME		QEMU_KEY_ESC1(1)
#define QEMU_KEY_END		QEMU_KEY_ESC1(4)
#define QEMU_KEY_PAGEUP		QEMU_KEY_ESC1(5)
#define QEMU_KEY_PAGEDOWN	QEMU_KEY_ESC1(6)
#define QEMU_KEY_DELETE		QEMU_KEY_ESC1(3)

#define QEMU_KEY_CTRL_UP		0xe400
#define QEMU_KEY_CTRL_DOWN		0xe401
#define QEMU_KEY_CTRL_LEFT		0xe402
#define QEMU_KEY_CTRL_RIGHT		0xe403
#define QEMU_KEY_CTRL_HOME		0xe404
#define QEMU_KEY_CTRL_END		0xe405
#define QEMU_KEY_CTRL_PAGEUP	0xe406
#define QEMU_KEY_CTRL_PAGEDOWN	0xe407


static void
block_signals(bool block)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	sigaddset(&set, SIGALRM);
	pthread_sigmask(block ? SIG_BLOCK : SIG_UNBLOCK, &set, NULL);
}


int
main(int argc, char **argv)
{
	block_signals(true);
	sMainThread = find_thread(NULL);
	QEMUApplication *app = new QEMUApplication(argc, argv);
	app->Run();
	delete app;
	return 0;
}


QEMUApplication::QEMUApplication(int argc, char **argv)
	:	BApplication("application/x-vnd.mmlr.QEMU"),
		fThread(0),
		fWindow(NULL)
{
	sApplication = this;

	fArgC = argc;
	fArgV = argv;

	fThread = spawn_thread(&RunQEMUMain, "qemu_main", B_LOW_PRIORITY, this);
	resume_thread(fThread);
}


bool
QEMUApplication::QuitRequested()
{
	if (sView != NULL)
		sView->QueueShutdownRequest();
	return true;
}


void
QEMUApplication::InitDisplay()
{
	fWindow = new QEMUWindow();
	fWindow->Show();

	BMessage reply;
	BMessenger(fWindow->Looper()).SendMessage(kMessageBlockSignals	, &reply);
}


int32
QEMUApplication::RunQEMUMain(void *arg)
{
	QEMUApplication *app = (QEMUApplication *)arg;

	block_signals(false);
	qemu_main(app->fArgC, app->fArgV, NULL);
	app->PostMessage(B_QUIT_REQUESTED);
	return B_OK;
}


QEMUWindow::QEMUWindow()
	:	BWindow(BRect(100, 100, 150, 150), "QEMU", B_TITLED_WINDOW,
			B_QUIT_ON_WINDOW_CLOSE | B_NOT_RESIZABLE)
{
	sWindow = this;
	fView = new QEMUView(Bounds());
	AddChild(fView);
}


void
QEMUWindow::MessageReceived(BMessage *message)
{
	if (message->what == kMessageBlockSignals) {
		block_signals(true);
		return;
	}

	BWindow::MessageReceived(message);
}


QEMUView::QEMUView(BRect frame)
	:	BView(frame, "fView", B_FOLLOW_ALL, B_WILL_DRAW),
		fBitmap(NULL)
{
	sView = this;
	fBitmap = new BBitmap(frame, 0, B_RGBA32);
	AddFilter(new BMessageFilter(B_ANY_DELIVERY, B_ANY_SOURCE, &MessageFilter));
}


QEMUView::~QEMUView()
{
	if (sFullScreen)
		BScreen().SetMode(&fDisplayMode);
}


void
QEMUView::AttachedToWindow()
{
	MakeFocus();
}


void
QEMUView::UpdateFullScreen()
{
	if (!sFullScreen)
		return;

	BScreen screen;
	display_mode current;
	display_mode *modes;
	display_mode *mode;
	uint32 count;

	screen.GetMode(&current);
	screen.GetModeList(&modes, &count);

	for (uint32 i = 0; i < count; i++) {
		mode = &modes[i];
		if (mode->virtual_width == sWidth
			&& mode->virtual_height == sHeight
			&& mode->space == current.space) {
			screen.SetMode(mode);
			break;
		}
	}

	sWindow->MoveTo(0, 0);
}


void
QEMUView::CenterMouse(bool &warp)
{
	BRect window = sWindow->Frame();
	BPoint center = window.LeftTop() + sCenter;
	set_mouse_position((int32)center.x, (int32)center.y);
	warp = true;
}


void
QEMUView::StartGrab(bool &grab)
{
	sApplication->HideCursor();
	sWindow->SetTitle("QEMU - Press Ctrl-Alt to exit grab");
	grab = true;
}


void
QEMUView::EndGrab(bool &grab, int32 modifiers)
{
	sApplication->ShowCursor();
	sWindow->SetTitle("QEMU");
	grab = false;

	// reset any set modifiers
	if (modifiers & B_LEFT_SHIFT_KEY)
		QueueKeycode(0x2a, false);
	if (modifiers & B_RIGHT_SHIFT_KEY)
		QueueKeycode(0x36, false);

	if (modifiers & B_LEFT_COMMAND_KEY)
		QueueKeycode(0x38, false);
	if (modifiers & B_RIGHT_COMMAND_KEY)
		QueueKeycode(0xb8, false);

	if (modifiers & B_LEFT_CONTROL_KEY)
		QueueKeycode(0x1d, false);
	if (modifiers & B_RIGHT_CONTROL_KEY)
		QueueKeycode(0x9d, false);

	if (modifiers & B_LEFT_OPTION_KEY)
		QueueKeycode(0xdb, false);
	if (modifiers & B_RIGHT_OPTION_KEY)
		QueueKeycode(0xdc, false);
}


void
QEMUView::QueueEvent(BMessage *event)
{
	if (!fEventQueue.Lock())
		return;

	fEventQueue.AddMessage(event);
	fEventQueue.Unlock();
}


void
QEMUView::QueueKeycode(uint8 keycode, bool keyDown)
{
	BMessage *event = new BMessage(kKeycodeEvent);
	event->AddUInt8("keycode", keycode);
	event->AddBool("keyDown", keyDown);
	sView->QueueEvent(event);
}


void
QEMUView::QueueKeysym(int32 keysym)
{
	BMessage *event = new BMessage(kKeysymEvent);
	event->AddInt32("keysym", keysym);
	sView->QueueEvent(event);
}


void
QEMUView::QueueMouseEvent(BPoint where, int32 deltaZ, int32 buttonState)
{
	int32 deltaX = where.x;
	int32 deltaY = where.y;

	if (!sAbsoluteMouse) {
		deltaX -= sCenter.x;
		deltaY -= sCenter.y;
	}

	BMessage *event = new BMessage(kMouseEvent);
	event->AddInt32("deltaX", deltaX);
	event->AddInt32("deltaY", deltaY);
	event->AddInt32("deltaZ", deltaZ);
	event->AddInt32("buttonState", buttonState);
	sView->QueueEvent(event);
}


void
QEMUView::QueueShutdownRequest()
{
	sView->QueueEvent(new BMessage(kShutdownRequest));
}


void
QEMUView::QueueConsoleSelect(uint8 console)
{
	BMessage *event = new BMessage(kConsoleSelectEvent);
	event->AddUInt8("console", console);
	sView->QueueEvent(event);
}


void
QEMUView::QueueInvalidation()
{
	sView->QueueEvent(new BMessage(kInvalidationRequest));
}


void
QEMUView::ProcessEvents()
{
	while (true) {
		if (!fEventQueue.Lock())
			return;

		BMessage *event = fEventQueue.NextMessage();
		fEventQueue.Unlock();

		if (event == NULL)
			return;

		switch (event->what) {
			case kKeycodeEvent:
			{
				uint8 keycode = 0;
				bool keyDown = false;
				if (event->FindUInt8("keycode", &keycode) != B_OK
					|| event->FindBool("keyDown", &keyDown) != B_OK) {
					break;
				}

				qemu_input_event_send_key_number(sCurrentConsole, keycode,
					keyDown);
				break;
			}

			case kKeysymEvent:
			{
				int32 keysym = 0;
				if (event->FindInt32("keysym", &keysym) != B_OK)
					break;

				kbd_put_keysym(keysym);
				break;
			}

			case kMouseEvent:
			{
				int32 deltaX = 0;
				int32 deltaY = 0;
				int32 deltaZ = 0;
				int32 buttonState = 0;
				if (event->FindInt32("deltaX", &deltaX) != B_OK
					|| event->FindInt32("deltaY", &deltaY) != B_OK
					|| event->FindInt32("deltaZ", &deltaZ) != B_OK
					|| event->FindInt32("buttonState", &buttonState) != B_OK) {
					break;
				}

				if (sAbsoluteMouse) {
					qemu_input_queue_abs(sCurrentConsole, INPUT_AXIS_X, deltaX,
						sWidth);
					qemu_input_queue_abs(sCurrentConsole, INPUT_AXIS_Y, deltaY,
						sHeight);
				} else {
					qemu_input_queue_rel(sCurrentConsole, INPUT_AXIS_X, deltaX);
					qemu_input_queue_rel(sCurrentConsole, INPUT_AXIS_Y, deltaY);
				}

				static int32 lastButtonState = 0;
				if (lastButtonState != buttonState) {
					// Haiku buttons are the same as QEMU
					static uint32_t buttonMap[INPUT_BUTTON_MAX] = {
						[INPUT_BUTTON_LEFT] = B_PRIMARY_MOUSE_BUTTON,
						[INPUT_BUTTON_MIDDLE] = B_TERTIARY_MOUSE_BUTTON,
						[INPUT_BUTTON_RIGHT] = B_SECONDARY_MOUSE_BUTTON
					};

					qemu_input_update_buttons(sCurrentConsole, buttonMap,
						lastButtonState, buttonState);
					lastButtonState = buttonState;
				}

			    qemu_input_event_sync();

				if (deltaZ != 0) {
					qemu_input_queue_btn(sCurrentConsole, deltaZ < 0
							? INPUT_BUTTON_WHEEL_UP : INPUT_BUTTON_WHEEL_DOWN,
						true);
				    qemu_input_event_sync();
					qemu_input_queue_btn(sCurrentConsole, deltaZ < 0
							? INPUT_BUTTON_WHEEL_UP : INPUT_BUTTON_WHEEL_DOWN,
						false);
				    qemu_input_event_sync();
				}

				break;
			}

			case kShutdownRequest:
				qemu_system_shutdown_request();
				break;

			case kConsoleSelectEvent:
			{
				uint8 console = 0;
				if (event->FindUInt8("console", &console) != B_OK)
					break;

				console_select(console);
				sCurrentConsole = qemu_console_lookup_by_index(console);
				sGraphicConsole = qemu_console_is_graphic(NULL);
				break;
			}

			case kInvalidationRequest:
				graphic_hw_invalidate(NULL);
				graphic_hw_update(NULL);
				break;
		}

		delete event;
	}
}


filter_result
QEMUView::MessageFilter(BMessage *message, BHandler **target,
	BMessageFilter *filter)
{
	static bool sMouseWarp = false;
	static int32 sMouseButtons = 0;
	static BPoint sMousePosition;
	bool keyDown = false;

	switch (message->what) {
		case B_KEY_DOWN:
		case B_UNMAPPED_KEY_DOWN:
			keyDown = true;
			// fall

		case B_KEY_UP:
		case B_UNMAPPED_KEY_UP: {
			int32 modifiers;
			message->FindInt32("modifiers", &modifiers);

			int32 key;
			message->FindInt32("key", &key);
			uint8 keycode = haiku_to_pc_key[(uint8)key];

			int32 mask = (B_COMMAND_KEY | B_CONTROL_KEY);
			if (!keyDown && sGrabInput && (modifiers & mask)
				&& (key == 0x5d || key == 0x5c)) {
					EndGrab(sGrabInput, modifiers);
					return B_SKIP_MESSAGE;
			}

			if (keyDown && (modifiers & mask) == mask) {
				switch (key) {
					case 0x3f: { /* f - fullscreen */
						BScreen screen;
						if (!sFullScreen) {
							screen.GetMode(&sView->fDisplayMode);
							sWindow->MoveTo(0, 0);
							sFullScreen = true;
						} else {
							screen.SetMode(&sView->fDisplayMode);
							sWindow->MoveTo(sView->fWindowLocation);
							sFullScreen = false;
						}

						UpdateFullScreen();
						QueueInvalidation();
						return B_SKIP_MESSAGE;
					} break;

					case 0x52: { /* m - pseudo fullscreen */
						BPoint location = sWindow->Frame().LeftTop();
						if (location.x == 0 && location.y == 0)
							sWindow->MoveTo(sPreviousLocation);
						else {
							sPreviousLocation = location;
							sWindow->MoveTo(0, 0);
						}

						QueueInvalidation();
						return B_SKIP_MESSAGE;
					} break;

					case 0x12 ... 0x1a: { /* 1 to 9 - switch console */
						QueueConsoleSelect(key - 0x12);
						QueueInvalidation();
						return B_SKIP_MESSAGE;
					} break;
				}
			} else if (!sGraphicConsole) {
				if (!keyDown)
					return B_SKIP_MESSAGE;

				int32 rawChar;
				message->FindInt32("raw_char", &rawChar);

				int keysym = 0;
				if (modifiers & (B_LEFT_CONTROL_KEY | B_RIGHT_CONTROL_KEY)) {
					switch(rawChar) {
						case B_UP_ARROW: keysym = QEMU_KEY_CTRL_UP; break;
						case B_DOWN_ARROW: keysym = QEMU_KEY_CTRL_DOWN; break;
						case B_LEFT_ARROW: keysym = QEMU_KEY_CTRL_LEFT; break;
						case B_RIGHT_ARROW: keysym = QEMU_KEY_CTRL_RIGHT; break;
						case B_HOME: keysym = QEMU_KEY_CTRL_HOME; break;
						case B_END: keysym = QEMU_KEY_CTRL_END; break;
						case B_PAGE_UP: keysym = QEMU_KEY_CTRL_PAGEUP; break;
						case B_PAGE_DOWN: keysym = QEMU_KEY_CTRL_PAGEDOWN; break;
					}
				} else {
					switch(rawChar) {
						case B_UP_ARROW: keysym = QEMU_KEY_UP; break;
						case B_DOWN_ARROW: keysym = QEMU_KEY_DOWN; break;
						case B_LEFT_ARROW: keysym = QEMU_KEY_LEFT; break;
						case B_RIGHT_ARROW: keysym = QEMU_KEY_RIGHT; break;
						case B_HOME: keysym = QEMU_KEY_HOME; break;
						case B_END: keysym = QEMU_KEY_END; break;
						case B_PAGE_UP: keysym = QEMU_KEY_PAGEUP; break;
						case B_PAGE_DOWN: keysym = QEMU_KEY_PAGEDOWN; break;
						case B_BACKSPACE: keysym = QEMU_KEY_BACKSPACE; break;
						case B_DELETE: keysym = QEMU_KEY_DELETE; break;
					}
				}

				if (keysym)
					QueueKeysym(keysym);
				else {
					const char *bytes;
					if (message->FindString("bytes", &bytes) == B_OK && bytes[0] != 0)
						QueueKeysym(bytes[0]);
				}
				return B_SKIP_MESSAGE;
			}

			QueueKeycode(keycode, keyDown);
			return B_SKIP_MESSAGE;
		} break;

		case B_MOUSE_MOVED: {
			if (!sGrabInput && !sAbsoluteMouse)
				break;

			if (sMouseWarp) {
				sMouseWarp = false;
				return B_SKIP_MESSAGE;
			}

			int32 transit;
			if (message->FindInt32("be:transit", &transit) == B_OK
				&& transit != B_ENTERED_VIEW && transit != B_INSIDE_VIEW) {
				break;
			}

			message->FindPoint("where", &sMousePosition);

			QueueMouseEvent(sMousePosition, 0, sMouseButtons);

			if (!sAbsoluteMouse)
				CenterMouse(sMouseWarp);

			return B_SKIP_MESSAGE;
		} break;

		case B_MOUSE_DOWN:
		case B_MOUSE_UP: {
			int32 buttons;
			message->FindInt32("buttons", &buttons);

			if (!sGrabInput && !sAbsoluteMouse) {
				if (message->what == B_MOUSE_DOWN
					&& (buttons & B_PRIMARY_MOUSE_BUTTON)) {
					CenterMouse(sMouseWarp);
					StartGrab(sGrabInput);
				}
				break;
			}

			sMouseButtons = buttons;
			message->FindPoint("where", &sMousePosition);

			QueueMouseEvent(sMousePosition, 0, sMouseButtons);
			return B_SKIP_MESSAGE;
		} break;

		case B_MOUSE_WHEEL_CHANGED: {
			if (!sGrabInput && !sAbsoluteMouse)
				break;

			float delta;
			message->FindFloat("be:wheel_delta_y", &delta);

			QueueMouseEvent(sMousePosition, (int32)delta, sMouseButtons);
			return B_SKIP_MESSAGE;
		} break;
	}

	return B_DISPATCH_MESSAGE;
}


void
QEMUView::Update(BPoint point, int width, int height)
{
	LockLooper();
	fBitmap->ImportBits(fFrameBuffer, fFrameBufferSize, fBytesPerRow,
		fColorSpace, point, point, width, height);

	Invalidate(BRect(point.x, point.y, point.x + width, point.y + height));
	UnlockLooper();
}


void
QEMUView::Draw(BRect updateRect)
{
	if (fBitmap == NULL)
		return;

	DrawBitmap(fBitmap, updateRect, updateRect);
}


void
QEMUView::UpdateFrameBuffer(int width, int height, uchar *bits,
	int bytesPerRow, int bitsPerPixel)
{
	if (LockLooper()) {
		delete fBitmap;
		fBitmap = new BBitmap(BRect(0, 0, width - 1, height - 1), 0, B_RGBA32);
		fFrameBuffer = bits;
		fFrameBufferSize = bytesPerRow * height;
		fBytesPerRow = bytesPerRow;

		switch (bitsPerPixel) {
			case 32:
				fColorSpace = B_RGB32;
				break;
			case 24:
				fColorSpace = B_RGB24;
				break;
			case 16:
				fColorSpace = B_RGB16;
				break;
			case 15:
				fColorSpace = B_RGB15;
				break;
			case 8:
				fColorSpace = B_CMAP8;
				break;
			default:
				printf("unsupported display depth %d\n", bitsPerPixel);
				break;
		}

		UnlockLooper();
	}
}


static void
haiku_update(DisplayChangeListener *dcl, int x, int y, int w, int h)
{
	//printf("updating x=%d y=%d w=%d h=%d\n", x, y, w, h);
	sView->Update(BPoint(x, y), w, h);
}


static void
haiku_switch(DisplayChangeListener *dcl, DisplaySurface *newSurface)
{
	//printf("resizing\n");
	sWidth = surface_width(newSurface);
	sHeight = surface_height(newSurface);
	sCenter.x = (int32)(sWidth / 2);
	sCenter.y = (int32)(sHeight / 2);
	sWindow->ResizeTo(sWidth - 1, sHeight - 1);
	sWindow->SetZoomLimits(sWidth, sHeight);
	sView->UpdateFrameBuffer(surface_width(newSurface),
		surface_height(newSurface), (uint8 *)surface_data(newSurface),
		surface_stride(newSurface), surface_bits_per_pixel(newSurface));
	sView->UpdateFullScreen();
}


static void
haiku_refresh(DisplayChangeListener *dcl)
{
	sView->ProcessEvents();
	if (sGraphicConsole)
		graphic_hw_update(NULL);
}


static void
haiku_mouse_mode_change(Notifier *notifier, void *data)
{
	sAbsoluteMouse = qemu_input_is_absolute();
	BCursor cursor(sAbsoluteMouse ? B_CURSOR_ID_NO_CURSOR
		: B_CURSOR_ID_SYSTEM_DEFAULT);

	if (sAbsoluteMouse) {
		if (sGrabInput)
			sView->EndGrab(sGrabInput, 0);
		sApplication->SetCursor(&cursor, true);
	} else
		sApplication->SetCursor(&cursor, true);
}


void
haiku_display_init(DisplayState *ds, int fullScreen)
{
	sApplication->InitDisplay();
	sFullScreen = fullScreen != 0;
	sGraphicConsole = qemu_console_is_graphic(NULL);
	sAbsoluteMouse = qemu_input_is_absolute();

	static DisplayChangeListenerOps sDisplayChangeListenerOps;
	sDisplayChangeListenerOps.dpy_name			= "haiku";
	sDisplayChangeListenerOps.dpy_gfx_update	= haiku_update;
	sDisplayChangeListenerOps.dpy_gfx_switch	= haiku_switch;
	sDisplayChangeListenerOps.dpy_refresh		= haiku_refresh;
	sDisplayChangeListenerOps.dpy_mouse_set		= NULL;
	sDisplayChangeListenerOps.dpy_cursor_define	= NULL;

	DisplayChangeListener *displayChangeListener
		= (DisplayChangeListener *)g_malloc0(sizeof(DisplayChangeListener));
	displayChangeListener->ops = &sDisplayChangeListenerOps;
	register_displaychangelistener(displayChangeListener);

	static Notifier sMouseModeChangeNotifier = { haiku_mouse_mode_change };
	qemu_add_mouse_mode_change_notifier(&sMouseModeChangeNotifier);
}
