package com.burpmirage.burp.ui;

import com.burpmirage.burp.util.HexUtils;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.function.Consumer;

/**
 * Fixed-length binary editor (Hex dump + continuous hex + ASCII).
 * <ul>
 *   <li>HEX and ASCII edits both work; dump applies HEX-only or ASCII-overwrite by caret region.</li>
 *   <li>Deleting in ASCII zeroes bytes ({@code 0x00}) instead of resurrecting old HEX.</li>
 *   <li>Bottom continuous HEX / ASCII panes live-sync the dump (caret preserved).</li>
 *   <li>{@code Ctrl+Z} / {@code Ctrl+Y} undo buffer snapshots (document undo is cleared by refresh).</li>
 * </ul>
 */
public final class HexEditorPanel extends JPanel {
    private enum EditSource { DUMP, CONTINUOUS, ASCII }

    private static final int UNDO_LIMIT = 80;

    private final JTextArea dumpArea = new JTextArea();
    private final JTextArea continuousArea = new JTextArea();
    private final JTextArea asciiArea = new JTextArea();
    private final JTextField searchField = new JTextField(12);
    private final JTextField replaceField = new JTextField(12);
    private final JTextField metaField = new JTextField();
    private final JLabel lengthLockLabel = new JLabel(" ");

    private byte[] data = new byte[0];
    private int lockedLength = -1;
    private Consumer<byte[]> changeListener = b -> {};
    private EditSource lastEdit = EditSource.DUMP;
    private boolean refreshing;
    private Timer liveSyncTimer;
    private final boolean hexOnly;
    private final Deque<byte[]> undoStack = new ArrayDeque<>();
    private final Deque<byte[]> redoStack = new ArrayDeque<>();

    public HexEditorPanel() {
        this(false);
    }

    public HexEditorPanel(boolean hexOnly) {
        super(new BorderLayout(6, 6));
        this.hexOnly = hexOnly;
        setBorder(new EmptyBorder(4, 4, 4, 4));
        setFocusable(true);

        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        dumpArea.setFont(mono);
        continuousArea.setFont(mono);
        asciiArea.setFont(mono);
        dumpArea.setLineWrap(false);
        continuousArea.setLineWrap(true);
        continuousArea.setWrapStyleWord(false);
        asciiArea.setLineWrap(true);

        metaField.setEditable(false);
        metaField.setBorder(new TitledBorder("Info"));
        metaField.setFont(mono.deriveFont(11f));
        lengthLockLabel.setFont(mono.deriveFont(Font.PLAIN, 11f));

        JPanel tools = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 6, 2));
        tools.add(new JLabel("Find:"));
        tools.add(searchField);
        tools.add(new JLabel("Replace:"));
        tools.add(replaceField);
        JButton applyBtn = new JButton("Replace All");
        applyBtn.addActionListener(e -> applyReplace());
        tools.add(applyBtn);
        JButton syncBtn = new JButton("Apply Edits");
        syncBtn.addActionListener(e -> applyFromEditors(true));
        tools.add(syncBtn);
        JButton undoBtn = new JButton("Undo");
        undoBtn.addActionListener(e -> undo());
        tools.add(undoBtn);
        tools.add(lengthLockLabel);

        JPanel north = new JPanel(new BorderLayout(0, 4));
        north.add(tools, BorderLayout.NORTH);
        north.add(metaField, BorderLayout.SOUTH);
        add(north, BorderLayout.NORTH);

        JScrollPane dumpScroll = new JScrollPane(dumpArea);
        dumpScroll.setBorder(new TitledBorder(
                "Hex Dump — edit HEX digits or ASCII column (delete → 00). Ctrl+Z undo."));

        if (hexOnly) {
            add(dumpScroll, BorderLayout.CENTER);
        } else {
            JScrollPane contScroll = new JScrollPane(continuousArea);
            contScroll.setBorder(new TitledBorder("Continuous Hex — live-syncs dump"));
            JScrollPane asciiScroll = new JScrollPane(asciiArea);
            asciiScroll.setBorder(new TitledBorder(
                    "ASCII — fixed length overwrite (Backspace/Delete → 00), live-syncs dump"));

            JSplitPane bottom = new JSplitPane(JSplitPane.VERTICAL_SPLIT, contScroll, asciiScroll);
            bottom.setResizeWeight(0.5);
            JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT, dumpScroll, bottom);
            main.setResizeWeight(0.55);
            add(main, BorderLayout.CENTER);
        }

        installFilters();
        installUndoKeys(this);
        installUndoKeys(dumpArea);
        installUndoKeys(continuousArea);
        installUndoKeys(asciiArea);

        dumpArea.getDocument().addDocumentListener(track(EditSource.DUMP));
        continuousArea.getDocument().addDocumentListener(track(EditSource.CONTINUOUS));
        asciiArea.getDocument().addDocumentListener(track(EditSource.ASCII));
    }

    private void installUndoKeys(JComponent c) {
        c.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK), "bm-undo");
        c.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_Y, InputEvent.CTRL_DOWN_MASK), "bm-redo");
        c.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_Z,
                        InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), "bm-redo");
        c.getActionMap().put("bm-undo", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                undo();
            }
        });
        c.getActionMap().put("bm-redo", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                redo();
            }
        });
    }

    private void installFilters() {
        // Continuous hex: max digits = lockedLength * 2
        ((AbstractDocument) continuousArea.getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
                    throws BadLocationException {
                replace(fb, offset, 0, string, attr);
            }

            @Override
            public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs)
                    throws BadLocationException {
                if (refreshing || lockedLength < 0) {
                    super.replace(fb, offset, length, text, attrs);
                    return;
                }
                String incoming = text == null ? "" : text;
                String current = fb.getDocument().getText(0, fb.getDocument().getLength());
                String next = current.substring(0, offset) + incoming + current.substring(offset + length);
                if (next.replaceAll("[^0-9A-Fa-f]", "").length() > lockedLength * 2) {
                    return;
                }
                super.replace(fb, offset, length, text, attrs);
            }
        });

        // ASCII pane: fixed-length overwrite. Delete/backspace writes NUL, does not shrink.
        ((AbstractDocument) asciiArea.getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
                    throws BadLocationException {
                if (string == null || string.isEmpty()) {
                    return;
                }
                replace(fb, offset, string.length(), string, attr);
            }

            @Override
            public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
                if (refreshing || lockedLength < 0) {
                    super.remove(fb, offset, length);
                    return;
                }
                // Replace deleted span with NUL so buffer length stays lockedLength.
                char[] zeros = new char[length];
                Arrays.fill(zeros, '\0');
                super.replace(fb, offset, length, new String(zeros), null);
            }

            @Override
            public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs)
                    throws BadLocationException {
                if (refreshing || lockedLength < 0) {
                    super.replace(fb, offset, length, text, attrs);
                    return;
                }
                String incoming = text == null ? "" : text;
                int docLen = fb.getDocument().getLength();
                if (docLen != lockedLength) {
                    // Allow refresh/setText to establish exact length.
                    super.replace(fb, offset, length, text, attrs);
                    return;
                }
                if (incoming.isEmpty()) {
                    char[] zeros = new char[length];
                    Arrays.fill(zeros, '\0');
                    super.replace(fb, offset, length, new String(zeros), attrs);
                    return;
                }
                // Overwrite in place; do not grow past lockedLength.
                int write = Math.min(incoming.length(), lockedLength - offset);
                if (write <= 0) {
                    return;
                }
                int replaceLen = Math.max(length, write);
                if (offset + replaceLen > lockedLength) {
                    replaceLen = lockedLength - offset;
                }
                String chunk = incoming.substring(0, write);
                if (write < replaceLen) {
                    chunk = chunk + String.valueOf('\0').repeat(replaceLen - write);
                }
                super.replace(fb, offset, replaceLen, chunk.substring(0, replaceLen), attrs);
            }
        });
    }

    private DocumentListener track(EditSource source) {
        return new DocumentListener() {
            private void mark() {
                if (refreshing) {
                    return;
                }
                lastEdit = source;
                scheduleLiveSync();
            }

            @Override
            public void insertUpdate(DocumentEvent e) {
                mark();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                mark();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                mark();
            }
        };
    }

    private void scheduleLiveSync() {
        if (refreshing) {
            return;
        }
        int delayMs = lastEdit == EditSource.DUMP ? 300 : 80;
        if (liveSyncTimer != null && liveSyncTimer.isRunning()) {
            liveSyncTimer.stop();
        }
        liveSyncTimer = new Timer(delayMs, e -> {
            if (!refreshing) {
                applyFromEditors(true);
            }
        });
        liveSyncTimer.setRepeats(false);
        liveSyncTimer.start();
    }

    public void setChangeListener(Consumer<byte[]> changeListener) {
        this.changeListener = changeListener != null ? changeListener : b -> {};
    }

    public void setData(byte[] bytes) {
        this.data = bytes != null ? bytes.clone() : new byte[0];
        this.lockedLength = this.data.length;
        undoStack.clear();
        redoStack.clear();
        updateLengthLockLabel();
        refreshViews(EditSource.DUMP, 0, 0, 0);
    }

    public int lockedLength() {
        return lockedLength;
    }

    public byte[] getData() {
        applyFromEditors(true);
        return data.clone();
    }

    public void setMeta(String text) {
        metaField.setText(text == null ? "" : text);
        metaField.setCaretPosition(0);
        metaField.setToolTipText(text);
    }

    public void setEditable(boolean editable) {
        dumpArea.setEditable(editable);
        continuousArea.setEditable(editable);
        asciiArea.setEditable(editable);
        searchField.setEditable(editable);
        replaceField.setEditable(editable);
    }

    public JTextArea dumpArea() {
        return dumpArea;
    }

    public JTextArea asciiArea() {
        return asciiArea;
    }

    private void updateLengthLockLabel() {
        if (lockedLength < 0) {
            lengthLockLabel.setText(" ");
        } else {
            lengthLockLabel.setText("Length locked: " + lockedLength
                    + " bytes · HEX/ASCII editable · delete→00 · Ctrl+Z undo");
        }
    }

    private void refreshViews(EditSource source, int dumpCaret, int contCaret, int asciiCaret) {
        refreshing = true;
        try {
            String dump = HexUtils.toHexDump(data);
            String cont = HexUtils.toContinuousHex(data);
            String ascii = new String(data, StandardCharsets.ISO_8859_1);
            dumpArea.setText(dump);
            continuousArea.setText(cont);
            asciiArea.setText(ascii);
            dumpArea.setCaretPosition(clamp(dumpCaret, dump.length()));
            continuousArea.setCaretPosition(clamp(contCaret, cont.length()));
            asciiArea.setCaretPosition(clamp(asciiCaret, ascii.length()));
        } finally {
            refreshing = false;
        }
    }

    private static int clamp(int caret, int len) {
        return Math.max(0, Math.min(caret, len));
    }

    private byte[] fitLocked(byte[] parsed) {
        if (lockedLength < 0) {
            return parsed != null ? parsed : new byte[0];
        }
        return HexUtils.fitLength(parsed, lockedLength);
    }

    private void applyFromEditors(boolean syncPrefixes) {
        int dumpCaret = dumpArea.getCaretPosition();
        int contCaret = continuousArea.getCaretPosition();
        int asciiCaret = asciiArea.getCaretPosition();
        byte[] previous = data.clone();
        byte[] parsed;
        EditSource source = hexOnly ? EditSource.DUMP : lastEdit;
        switch (source) {
            case ASCII -> parsed = asciiBytesFixed();
            case CONTINUOUS -> {
                String cleaned = continuousArea.getText() == null
                        ? ""
                        : continuousArea.getText().replaceAll("[^0-9A-Fa-f]", "");
                // Skip while still typing (odd length or incomplete vs lock).
                if (lockedLength >= 0 && cleaned.length() != lockedLength * 2) {
                    return;
                }
                parsed = HexUtils.fromContinuousHex(continuousArea.getText());
            }
            case DUMP -> {
                String dump = dumpArea.getText();
                if (dump == null || dump.isBlank()) {
                    parsed = data;
                    break;
                }
                boolean inAscii = HexUtils.isDumpCaretInAsciiColumn(dump, dumpCaret);
                if (inAscii) {
                    // ASCII overwrite: shorter column → remaining bytes 0x00
                    parsed = HexUtils.fromHexDump(dump);
                } else {
                    parsed = HexUtils.fromHexDumpHexOnly(dump);
                    // Incomplete hex nibble/token mid-edit — don't zero-pad the rest away.
                    if (lockedLength >= 0 && parsed.length != lockedLength) {
                        return;
                    }
                }
            }
            default -> parsed = data;
        }
        parsed = fitLocked(parsed);
        if (syncPrefixes) {
            parsed = HexUtils.syncLengthPrefixes(previous, parsed);
        }
        if (Arrays.equals(previous, parsed)) {
            // Still refresh so HEX/ASCII/continuous panes stay visually in sync.
            refreshViews(source, dumpCaret, contCaret, asciiCaret);
            return;
        }
        pushUndo(previous);
        data = parsed;
        refreshViews(source, dumpCaret, contCaret, asciiCaret);
        changeListener.accept(data);
    }

    /** ASCII pane → bytes, always exactly lockedLength (NUL-padded). */
    private byte[] asciiBytesFixed() {
        byte[] raw = asciiArea.getText().getBytes(StandardCharsets.ISO_8859_1);
        return fitLocked(raw);
    }

    private void pushUndo(byte[] previous) {
        undoStack.push(previous.clone());
        while (undoStack.size() > UNDO_LIMIT) {
            undoStack.removeLast();
        }
        redoStack.clear();
    }

    private void undo() {
        if (undoStack.isEmpty()) {
            return;
        }
        redoStack.push(data.clone());
        data = undoStack.pop();
        lockedLength = data.length;
        refreshViews(lastEdit, dumpArea.getCaretPosition(),
                continuousArea.getCaretPosition(), asciiArea.getCaretPosition());
        changeListener.accept(data);
    }

    private void redo() {
        if (redoStack.isEmpty()) {
            return;
        }
        undoStack.push(data.clone());
        data = redoStack.pop();
        lockedLength = data.length;
        refreshViews(lastEdit, dumpArea.getCaretPosition(),
                continuousArea.getCaretPosition(), asciiArea.getCaretPosition());
        changeListener.accept(data);
    }

    private void applyReplace() {
        applyFromEditors(true);
        byte[] previous = data.clone();
        String search = searchField.getText();
        String replace = replaceField.getText();
        if (search == null || search.isEmpty()) {
            return;
        }
        byte[] next;
        if (search.matches("(?i)^[0-9a-f\\s]+$") && search.replaceAll("\\s", "").length() >= 2) {
            next = HexUtils.replaceHexPattern(data, search, replace);
        } else {
            next = HexUtils.replaceAscii(data, search, replace == null ? "" : replace);
        }
        next = fitLocked(next);
        next = HexUtils.syncLengthPrefixes(previous, next);
        if (!Arrays.equals(previous, next)) {
            pushUndo(previous);
            data = next;
        }
        lastEdit = EditSource.DUMP;
        refreshViews(EditSource.DUMP, 0, 0, 0);
        changeListener.accept(data);
    }

    public void clear() {
        lockedLength = -1;
        undoStack.clear();
        redoStack.clear();
        setData(new byte[0]);
        setMeta("");
    }

    public void runOnEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeLater(r);
        }
    }

    @Override
    public Dimension getMinimumSize() {
        return new Dimension(200, 120);
    }
}
