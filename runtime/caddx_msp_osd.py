"""MSP DisplayPort OSD — the CGC OSD plane on UDP 9200.

Oracle: CGC v0.3.5 `MspFrameReassembler`, `MspOsdParser`, `MspDisplayPortDecoder`
(`CaddxGroundConfiguration.dll` `d42ff30c…`).

UDP 9200 is **native MSP**, not another FE/EF stream. CGC opens it by sending the
four literal bytes `24 4D 53 50` (`"$MSP"`) -- `MainPresenter.StartOsdChannel:193` --
after which the flight controller pushes MSP frames continuously. Nothing else is
sent; the channel is one kick and then a read loop.

    $ M <dir> <len> <cmd> <payload…> <crc>            v1, total = 6 + len
    $ X <dir> <flag> <cmd16 LE> <len16 LE> <payload…> <crc>   v2, total = 9 + len

MSP command **182** is `MSP_DISPLAYPORT`. Its payload[0] is a sub-command:

    0 Heartbeat   1 Release   2 ClearScreen   3 WriteString
    4 DrawScreen  5 Options   6 Sys           53 full-frame variant

The decoder keeps a character grid and mutates it: WriteString paints, ClearScreen
and Release wipe, Options resizes, and **DrawScreen is what makes a frame visible**.
Cells are `(page << 8) | char` where page is `attribute & 3`.

Grid sizes are fixed by Options mode (`MspDisplayPortDecoder.SetMode`):
mode 0 = 30x16, 1 = 50x18, 2 = 60x22 (the default), 3 = 53x20.

**Rendering is ours.** CGC composites the grid into a video overlay through
GStreamer and a Win32 sink. We have no video surface, so this module returns the
grid as text rows and lets the page show it as a character display. That is more
readable than stock in a window and strictly less than stock over video; say so
rather than implying an overlay.
"""

from __future__ import annotations

MSP_HEADER = 0x24          # '$'   MspFrameReassembler.FrameHeader
MSP_V1 = 0x4D              # 'M'   MarkerV1
MSP_V2 = 0x58              # 'X'   MarkerV2
V1_OVERHEAD = 6
V2_OVERHEAD = 9
DEFAULT_MAX_BUFFER = 8192  # DefaultMaxBufferBytes

MSP_DISPLAYPORT = 182      # MspOsdParser.MspDisplayPortCommand
FULL_FRAME_SUBCOMMAND = 53

KICK = b'\x24\x4D\x53\x50'   # "$MSP"

HEARTBEAT, RELEASE, CLEAR_SCREEN, WRITE_STRING, DRAW_SCREEN, OPTIONS, SYS = range(7)
SUBCOMMAND_NAMES = {HEARTBEAT: 'HEARTBEAT', RELEASE: 'RELEASE', CLEAR_SCREEN: 'CLEAR_SCREEN',
                    WRITE_STRING: 'WRITE_STRING', DRAW_SCREEN: 'DRAW_SCREEN',
                    OPTIONS: 'OPTIONS', SYS: 'SYS', FULL_FRAME_SUBCOMMAND: 'FULL_FRAME'}

# MspDisplayPortDecoder.SetMode. Any other mode value is ignored, not defaulted.
MODES = {0: (30, 16), 1: (50, 18), 2: (60, 22), 3: (53, 20)}
MAX_COLUMNS, MAX_ROWS = 60, 22


def split_frames(buffer: bytes) -> tuple[list[dict], bytes]:
    """Split a byte buffer into complete MSP frames plus an unconsumed tail.

    Transcribed from `MspFrameReassembler.Append`/the scan loop: a byte that is not
    `$` is skipped, a `$` not followed by `M` or `X` is skipped, and a frame whose
    declared length overruns the buffer ends the scan so the tail is retained.
    """
    frames, i, n = [], 0, len(buffer)
    tail_start = 0
    while i < n:
        if buffer[i] != MSP_HEADER:
            i += 1
            tail_start = i
            continue
        if n - i < 3:
            break
        marker = buffer[i + 1]
        if marker == MSP_V1:
            if n - i < 4:
                break
            total = V1_OVERHEAD + buffer[i + 3]
            if n - i < total:
                break
            frames.append({'version': 1, 'direction': buffer[i + 2],
                           'length': buffer[i + 3], 'command': buffer[i + 4],
                           'payload': bytes(buffer[i + 5:i + 5 + buffer[i + 3]]),
                           'raw': bytes(buffer[i:i + total])})
        elif marker == MSP_V2:
            if n - i < 8:
                break
            length = buffer[i + 6] | (buffer[i + 7] << 8)
            total = V2_OVERHEAD + length
            if n - i < total:
                break
            frames.append({'version': 2, 'direction': buffer[i + 2],
                           'flag': buffer[i + 3],
                           'command': buffer[i + 4] | (buffer[i + 5] << 8),
                           'length': length,
                           'payload': bytes(buffer[i + 8:i + 8 + length]),
                           'raw': bytes(buffer[i:i + total])})
        else:
            i += 1
            tail_start = i
            continue
        i += total
        tail_start = i
    return frames, bytes(buffer[tail_start:])


def parse_displayport(frame: dict) -> dict | None:
    """Decode one MSP_DISPLAYPORT frame into a sub-command record.

    Returns None for any other MSP command. Malformed DisplayPort payloads produce
    a record carrying `issue` rather than raising, because this runs against a live
    push stream where one bad frame must not stop the display.
    """
    if frame.get('command') != MSP_DISPLAYPORT:
        return None
    payload = frame.get('payload') or b''
    if not payload:
        return {'issue': 'DisplayPortTooShort',
                'message': 'MSP_DISPLAYPORT payload does not contain a subcommand.'}
    sub = payload[0]
    if sub == FULL_FRAME_SUBCOMMAND:
        return {'subcommand': FULL_FRAME_SUBCOMMAND, 'name': 'FULL_FRAME',
                'characters': bytes(payload[1:])}
    rec = {'subcommand': sub, 'name': SUBCOMMAND_NAMES.get(sub, f'UNKNOWN({sub})')}
    if sub == WRITE_STRING:
        if len(payload) < 4:
            return {'issue': 'DisplayPortTooShort',
                    'message': 'WRITE_STRING requires row, column and attribute.'}
        rec.update({'row': payload[1], 'column': payload[2], 'attribute': payload[3],
                    'characters': bytes(payload[4:])})
    elif sub == OPTIONS:
        # Options carries the font/mode pair; the decoder only consumes the mode.
        rec['font'] = payload[1] if len(payload) > 1 else 0
        rec['mode'] = payload[2] if len(payload) > 2 else 0
    return rec


class DisplayPortScreen:
    """The 60x22 character grid, mutated by DisplayPort sub-commands.

    Mirrors `MspDisplayPortDecoder`: WriteString paints, Release and ClearScreen
    wipe, Options resizes and wipes, and **DrawScreen is what commits a frame**.
    Nothing is displayable until a DrawScreen arrives, which is why `apply` reports
    whether one did.
    """

    def __init__(self):
        self.columns, self.rows = MODES[2]
        self.cells = [[0] * MAX_COLUMNS for _ in range(MAX_ROWS)]
        self.draw_count = 0
        self.last_mode = 2

    def clear(self) -> None:
        for row in self.cells:
            for i in range(MAX_COLUMNS):
                row[i] = 0

    def set_mode(self, mode: int) -> None:
        if mode not in MODES:
            return                      # vendor: `default: return` -- no resize, no clear
        self.columns, self.rows = MODES[mode]
        self.last_mode = mode
        self.clear()

    def write_full_frame(self, rec: dict) -> None:
        """Paint sub-command 53, the FULL_FRAME variant.

        parse_displayport has decoded this all along and `apply` ignored it,
        so nothing was ever painted from a device that uses it -- which is
        every frame this VRX sends. Measured 2026-10-04: 199 reads from a
        live unit, function 182 every time, sub-command 53 every time.

        The payload is the whole grid, row-major, one byte per cell. A short
        payload fills what it covers and leaves the rest alone rather than
        clearing: a truncated read is a partial update, not a blank screen.
        """
        chars = rec.get('characters') or b''
        for i, ch in enumerate(chars):
            r, c = divmod(i, self.columns)
            if r >= self.rows:
                break
            self.cells[r][c] = ch

    def write_string(self, rec: dict) -> None:
        row, col = rec.get('row', 0), rec.get('column', 0)
        chars = rec.get('characters') or b''
        if row >= self.rows or col >= self.columns:
            return
        page = rec.get('attribute', 0) & 3
        for i in range(min(self.columns - col, len(chars))):
            self.cells[row][col + i] = (page << 8) | chars[i]

    def apply(self, records) -> bool:
        drew = False
        for rec in records:
            if not rec or rec.get('issue'):
                continue
            sub = rec.get('subcommand')
            if sub in (RELEASE, CLEAR_SCREEN):
                self.clear()
            elif sub == WRITE_STRING:
                self.write_string(rec)
            elif sub == OPTIONS:
                self.set_mode(rec.get('mode', 0))
            elif sub == FULL_FRAME_SUBCOMMAND:
                # A full frame IS the frame: it carries the whole grid, so it
                # both paints and commits. Requiring a separate DrawScreen
                # would leave a device that only sends 53 permanently blank.
                self.write_full_frame(rec)
                drew = True
                self.draw_count += 1
            elif sub == DRAW_SCREEN:
                drew = True
                self.draw_count += 1
        return drew

    def text_rows(self) -> list[str]:
        """The grid as printable text.

        MSP OSD character codes index a font page, not ASCII, so a code outside the
        printable range has no text equivalent. Those are rendered as a space rather
        than as a substitute glyph -- inventing a character would misreport the OSD.
        """
        out = []
        for r in range(self.rows):
            row = self.cells[r]
            out.append(''.join(
                chr(c & 0xFF) if 0x20 <= (c & 0xFF) < 0x7F else ' '
                for c in row[:self.columns]).rstrip())
        return out

    def reading(self) -> dict:
        cells = [[{'char': c & 0xFF, 'page': c >> 8} for c in row[:self.columns]]
                 for row in self.cells[:self.rows]]
        occupied = sum(1 for row in self.cells[:self.rows]
                       for c in row[:self.columns] if c)
        return {'columns': self.columns, 'rows': self.rows, 'mode': self.last_mode,
                'draw_count': self.draw_count, 'occupied_cells': occupied,
                'text_rows': self.text_rows(), 'cells': cells}


def selftest() -> dict:
    scr = DisplayPortScreen()
    # A v1 DisplayPort WRITE_STRING at row 2 col 4, then DRAW_SCREEN.
    def v1(cmd, payload):
        return bytes([MSP_HEADER, MSP_V1, ord('<'), len(payload), cmd]) + payload + b'\x00'
    body = v1(MSP_DISPLAYPORT, bytes([WRITE_STRING, 2, 4, 0]) + b'ALT 120') \
         + v1(MSP_DISPLAYPORT, bytes([DRAW_SCREEN]))
    frames, tail = split_frames(body)
    assert len(frames) == 2 and tail == b''
    recs = [parse_displayport(f) for f in frames]
    assert scr.apply(recs) is True
    assert scr.text_rows()[2] == '    ALT 120'
    # A truncated frame must be retained, not consumed.
    frames2, tail2 = split_frames(body[:-3])
    assert len(frames2) == 1 and len(tail2) > 0
    return {'ok': True, 'columns': scr.columns, 'rows': scr.rows}


if __name__ == '__main__':
    print(selftest())
