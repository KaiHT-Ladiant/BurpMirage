package com.burpmirage.burp.ui;

import com.burpmirage.burp.util.HexUtils;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
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
 * Packet editor with Burp-like tabs: Info (Pretty) / HEX / ASCII (Raw).
 * Insert/delete shifts length; dump offsets are read-only; Forward/Send should call
 * {@link HexUtils#prepareEditedPacket} for Content-Length / frame-length sync.
 */
public final class HexEditorPanel extends JPanel {
    private enum EditSource { DUMP, CONTINUOUS, ASCII }

    private static final int UNDO_LIMIT = 80;

    private final JTextArea dumpArea = new JTextArea();
    private final JTextArea continuousArea = new JTextArea();
    private final JTextArea asciiArea = new JTextArea();
    private final JTextArea infoPreview = new JTextArea();
    private final JTextField searchField = new JTextField(12);
    private final JTextField replaceField = new JTextField(12);
    private final JTextField metaField = new JTextField();
    private final JLabel lengthLockLabel = new JLabel(" ");
    private final JTabbedPane tabs = new JTabbedPane();

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
        infoPreview.setFont(mono);
        dumpArea.setLineWrap(false);
        continuousArea.setLineWrap(true);
        continuousArea.setWrapStyleWord(false);
        asciiArea.setLineWrap(true);
        infoPreview.setLineWrap(true);
        infoPreview.setWrapStyleWord(false);
        infoPreview.setEditable(false);

        metaField.setEditable(false);
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
        add(tools, BorderLayout.NORTH);

        // Info ≈ Burp Pretty — metadata + printable preview (read-only)
        JPanel infoTab = new JPanel(new BorderLayout(4, 4));
        metaField.setBorder(new TitledBorder("Info"));
        infoPreview.setBorder(new TitledBorder("Preview (printable)"));
        infoTab.add(metaField, BorderLayout.NORTH);
        infoTab.add(new JScrollPane(infoPreview), BorderLayout.CENTER);

        // HEX ≈ Burp Hex — dump (+ continuous when not hexOnly)
        JScrollPane dumpScroll = new JScrollPane(dumpArea);
        dumpScroll.setBorder(new TitledBorder(
                "Hex Dump — offsets read-only · insert/delete shifts length · Ctrl+Z"));
        JPanel hexTab = new JPanel(new BorderLayout(4, 4));
        if (hexOnly) {
            hexTab.add(dumpScroll, BorderLayout.CENTER);
        } else {
            JScrollPane contScroll = new JScrollPane(continuousArea);
            contScroll.setBorder(new TitledBorder("Continuous Hex"));
            JSplitPane hexSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, dumpScroll, contScroll);
            hexSplit.setResizeWeight(0.7);
            hexTab.add(hexSplit, BorderLayout.CENTER);
        }

        // ASCII ≈ Burp Raw — editable ISO-8859-1 / text view
        JScrollPane asciiScroll = new JScrollPane(asciiArea);
        asciiScroll.setBorder(new TitledBorder("ASCII / Raw — insert/delete shifts length"));

        tabs.addTab("Info", infoTab);
        tabs.addTab("HEX", hexTab);
        tabs.addTab("ASCII", asciiScroll);
        tabs.setSelectedIndex(1); // default HEX like Burp hex inspectors often used
        tabs.addChangeListener(e -> {
            if (!refreshing) {
                applyFromEditors(true);
            }
        });
        add(tabs, BorderLayout.CENTER);

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
        // Continuous hex: allow grow/shrink (only hex digits + whitespace). Cap runaway paste.
        ((AbstractDocument) continuousArea.getDocument()).setDocumentFilter(new DocumentFilter() {
            private static final int MAX_DIGITS = 2 * 1024 * 1024;

            @Override
            public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
                    throws BadLocationException {
                replace(fb, offset, 0, string, attr);
            }

            @Override
            public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs)
                    throws BadLocationException {
                if (refreshing) {
                    super.replace(fb, offset, length, text, attrs);
                    return;
                }
                String incoming = text == null ? "" : text.replaceAll("[^0-9A-Fa-f\\s]", "");
                String current = fb.getDocument().getText(0, fb.getDocument().getLength());
                String next = current.substring(0, offset) + incoming + current.substring(offset + length);
                if (next.replaceAll("[^0-9A-Fa-f]", "").length() > MAX_DIGITS) {
                    return;
                }
                super.replace(fb, offset, length, incoming, attrs);
            }
        });

        // Dump: block edits in the offset column (addresses are decorative / regenerated).
        ((AbstractDocument) dumpArea.getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
                    throws BadLocationException {
                replace(fb, offset, 0, string, attr);
            }

            @Override
            public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
                if (refreshing) {
                    super.remove(fb, offset, length);
                    return;
                }
                String doc = fb.getDocument().getText(0, fb.getDocument().getLength());
                if (touchesOffsetColumn(doc, offset, length)) {
                    int hexStart = HexUtils.dumpHexColumnStart(doc, offset);
                    dumpArea.setCaretPosition(clamp(hexStart, doc.length()));
                    return;
                }
                super.remove(fb, offset, length);
            }

            @Override
            public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs)
                    throws BadLocationException {
                if (refreshing) {
                    super.replace(fb, offset, length, text, attrs);
                    return;
                }
                String doc = fb.getDocument().getText(0, fb.getDocument().getLength());
                if (touchesOffsetColumn(doc, offset, Math.max(length, text == null ? 0 : 1))) {
                    int hexStart = HexUtils.dumpHexColumnStart(doc, offset);
                    dumpArea.setCaretPosition(clamp(hexStart, doc.length()));
                    // If selection was only in offset, ignore; otherwise apply at hex start.
                    if (length > 0 && text != null && !text.isEmpty()
                            && !HexUtils.isDumpCaretInOffsetColumn(doc, offset)) {
                        super.replace(fb, hexStart, 0, text, attrs);
                    }
                    return;
                }
                super.replace(fb, offset, length, text, attrs);
            }

            private boolean touchesOffsetColumn(String doc, int offset, int length) {
                if (HexUtils.isDumpCaretInOffsetColumn(doc, offset)) {
                    return true;
                }
                if (length <= 0) {
                    return false;
                }
                int end = Math.min(doc.length(), offset + length - 1);
                return HexUtils.isDumpCaretInOffsetColumn(doc, end);
            }
        });

        // ASCII pane: free insert/delete (length follows text).
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
            lengthLockLabel.setText("Length: " + lockedLength
                    + " bytes · insert/delete shifts · offsets read-only · Ctrl+Z undo");
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
            infoPreview.setText(buildInfoPreview(data));
            dumpArea.setCaretPosition(clamp(dumpCaret, dump.length()));
            continuousArea.setCaretPosition(clamp(contCaret, cont.length()));
            asciiArea.setCaretPosition(clamp(asciiCaret, ascii.length()));
        } finally {
            refreshing = false;
        }
    }

    private static String buildInfoPreview(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        if (HexUtils.looksLikeHttpMessage(bytes)) {
            return new String(bytes, StandardCharsets.ISO_8859_1);
        }
        StringBuilder sb = new StringBuilder(bytes.length);
        for (byte value : bytes) {
            int b = value & 0xFF;
            if (b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b < 0x7F)) {
                sb.append((char) b);
            } else {
                sb.append('.');
            }
        }
        return sb.toString();
    }

    private static int clamp(int caret, int len) {
        return Math.max(0, Math.min(caret, len));
    }

    private void applyFromEditors(boolean syncPrefixes) {
        int dumpCaret = dumpArea.getCaretPosition();
        int contCaret = continuousArea.getCaretPosition();
        int asciiCaret = asciiArea.getCaretPosition();
        byte[] previous = data.clone();
        byte[] parsed;
        EditSource source = hexOnly ? EditSource.DUMP : lastEdit;
        switch (source) {
            case ASCII -> parsed = asciiArea.getText().getBytes(StandardCharsets.ISO_8859_1);
            case CONTINUOUS -> {
                String cleaned = continuousArea.getText() == null
                        ? ""
                        : continuousArea.getText().replaceAll("[^0-9A-Fa-f]", "");
                // Skip while still typing a half-byte.
                if ((cleaned.length() & 1) == 1) {
                    return;
                }
                parsed = HexUtils.fromContinuousHex(continuousArea.getText());
            }
            case DUMP -> {
                String dump = dumpArea.getText();
                if (dump == null || dump.isBlank()) {
                    parsed = new byte[0];
                    break;
                }
                if (HexUtils.dumpHexDigitsIncomplete(dump)
                        && !HexUtils.isDumpCaretInAsciiColumn(dump, dumpCaret)) {
                    // Mid-nibble HEX edit — wait for a complete byte.
                    return;
                }
                boolean inAscii = HexUtils.isDumpCaretInAsciiColumn(dump, dumpCaret);
                if (inAscii) {
                    // ASCII column edits can shorten/lengthen that line's bytes → whole buffer shifts.
                    parsed = HexUtils.fromHexDump(dump);
                } else {
                    parsed = HexUtils.fromHexDumpHexOnly(dump);
                }
            }
            default -> parsed = data;
        }
        if (parsed == null) {
            parsed = new byte[0];
        }
        // Same-length edits: keep framing length-prefix sync. Length changes: accept push/pull as-is.
        if (syncPrefixes && previous.length == parsed.length && previous.length > 0) {
            parsed = HexUtils.applyLogicalLength(previous, parsed);
        }
        if (Arrays.equals(previous, parsed)) {
            refreshViews(source, dumpCaret, contCaret, asciiCaret);
            return;
        }
        pushUndo(previous);
        data = parsed;
        lockedLength = data.length;
        updateLengthLockLabel();
        refreshViews(source, dumpCaret, contCaret, asciiCaret);
        changeListener.accept(data);
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
        if (previous.length == next.length && previous.length > 0) {
            next = HexUtils.applyLogicalLength(previous, next);
        }
        if (!Arrays.equals(previous, next)) {
            pushUndo(previous);
            data = next;
            lockedLength = data.length;
            updateLengthLockLabel();
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
