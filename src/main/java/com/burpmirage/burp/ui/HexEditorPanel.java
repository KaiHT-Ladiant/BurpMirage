package com.burpmirage.burp.ui;

import com.burpmirage.burp.util.HexUtils;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
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
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

/**
 * Dual-pane Hex dump + continuous hex / ASCII editor.
 * Edited payload length is locked to the buffer size loaded via {@link #setData(byte[])}
 * (in-place Winsock hooks cannot grow the original buffer).
 */
public final class HexEditorPanel extends JPanel {
    private enum EditSource { DUMP, CONTINUOUS, ASCII }

    private final JTextArea dumpArea = new JTextArea();
    private final JTextArea continuousArea = new JTextArea();
    private final JTextArea asciiArea = new JTextArea();
    private final JTextField searchField = new JTextField(12);
    private final JTextField replaceField = new JTextField(12);
    private final JTextField metaField = new JTextField();
    private final JLabel lengthLockLabel = new JLabel(" ");

    private byte[] data = new byte[0];
    /** Fixed byte length; -1 means unlocked (empty / cleared). */
    private int lockedLength = -1;
    private Consumer<byte[]> changeListener = b -> {};
    private EditSource lastEdit = EditSource.DUMP;
    private boolean refreshing;
    private final boolean hexOnly;

    public HexEditorPanel() {
        this(false);
    }

    public HexEditorPanel(boolean hexOnly) {
        super(new BorderLayout(6, 6));
        this.hexOnly = hexOnly;
        setBorder(new EmptyBorder(4, 4, 4, 4));

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
        syncBtn.addActionListener(e -> applyFromEditors());
        tools.add(syncBtn);
        tools.add(lengthLockLabel);

        JPanel north = new JPanel(new BorderLayout(0, 4));
        north.add(tools, BorderLayout.NORTH);
        north.add(metaField, BorderLayout.SOUTH);
        add(north, BorderLayout.NORTH);

        JScrollPane dumpScroll = new JScrollPane(dumpArea);
        dumpScroll.setBorder(new TitledBorder("Hex Dump — HEX or ASCII column ( |...| ) editable"));

        if (hexOnly) {
            add(dumpScroll, BorderLayout.CENTER);
        } else {
            JScrollPane contScroll = new JScrollPane(continuousArea);
            contScroll.setBorder(new TitledBorder("Continuous Hex"));
            JScrollPane asciiScroll = new JScrollPane(asciiArea);
            asciiScroll.setBorder(new TitledBorder("ASCII (ISO-8859-1) — string edits apply on Forward/Send"));

            JSplitPane bottom = new JSplitPane(JSplitPane.VERTICAL_SPLIT, contScroll, asciiScroll);
            bottom.setResizeWeight(0.5);
            JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT, dumpScroll, bottom);
            main.setResizeWeight(0.55);
            add(main, BorderLayout.CENTER);
        }

        installLengthFilters();
        dumpArea.getDocument().addDocumentListener(track(EditSource.DUMP));
        continuousArea.getDocument().addDocumentListener(track(EditSource.CONTINUOUS));
        asciiArea.getDocument().addDocumentListener(track(EditSource.ASCII));
    }

    private void installLengthFilters() {
        ((AbstractDocument) continuousArea.getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
                    throws BadLocationException {
                if (string == null) {
                    return;
                }
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
                String cleaned = next.replaceAll("[^0-9A-Fa-f]", "");
                int maxHexChars = lockedLength * 2;
                if (cleaned.length() > maxHexChars) {
                    // Reject growth beyond locked byte length (hex digits).
                    return;
                }
                super.replace(fb, offset, length, text, attrs);
            }
        });

        ((AbstractDocument) asciiArea.getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
                    throws BadLocationException {
                if (string == null) {
                    return;
                }
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
                int nextLen = fb.getDocument().getLength() - length + incoming.length();
                if (nextLen > lockedLength) {
                    return;
                }
                super.replace(fb, offset, length, text, attrs);
            }
        });
    }

    private DocumentListener track(EditSource source) {
        return new DocumentListener() {
            private void mark() {
                if (!refreshing) {
                    lastEdit = source;
                }
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

    public void setChangeListener(Consumer<byte[]> changeListener) {
        this.changeListener = changeListener != null ? changeListener : b -> {};
    }

    public void setData(byte[] bytes) {
        this.data = bytes != null ? bytes.clone() : new byte[0];
        this.lockedLength = this.data.length;
        updateLengthLockLabel();
        refreshViews();
    }

    public int lockedLength() {
        return lockedLength;
    }

    public byte[] getData() {
        applyFromEditors();
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
            lengthLockLabel.setText("Length locked: " + lockedLength + " bytes (truncate/pad on apply)");
        }
    }

    private void refreshViews() {
        refreshing = true;
        try {
            dumpArea.setText(HexUtils.toHexDump(data));
            continuousArea.setText(HexUtils.toContinuousHex(data));
            asciiArea.setText(new String(data, StandardCharsets.ISO_8859_1));
            dumpArea.setCaretPosition(0);
            continuousArea.setCaretPosition(0);
            asciiArea.setCaretPosition(0);
        } finally {
            refreshing = false;
        }
    }

    private byte[] fitLocked(byte[] parsed) {
        if (lockedLength < 0) {
            return parsed != null ? parsed : new byte[0];
        }
        return HexUtils.fitLength(parsed, lockedLength);
    }

    private void applyFromEditors() {
        byte[] parsed;
        if (hexOnly) {
            lastEdit = EditSource.DUMP;
        }
        switch (lastEdit) {
            case ASCII -> parsed = asciiArea.getText().getBytes(StandardCharsets.ISO_8859_1);
            case CONTINUOUS -> parsed = HexUtils.fromContinuousHex(continuousArea.getText());
            case DUMP -> {
                String dump = dumpArea.getText();
                if (dump != null && !dump.isBlank()) {
                    parsed = HexUtils.fromHexDump(dump);
                } else if (continuousArea.getText() != null && !continuousArea.getText().isBlank()) {
                    parsed = HexUtils.fromContinuousHex(continuousArea.getText());
                } else {
                    parsed = asciiArea.getText().getBytes(StandardCharsets.ISO_8859_1);
                }
            }
            default -> parsed = data;
        }
        data = fitLocked(parsed);
        refreshViews();
        changeListener.accept(data);
    }

    private void applyReplace() {
        applyFromEditors();
        String search = searchField.getText();
        String replace = replaceField.getText();
        if (search == null || search.isEmpty()) {
            return;
        }
        if (search.matches("(?i)^[0-9a-f\\s]+$") && search.replaceAll("\\s", "").length() >= 2) {
            data = HexUtils.replaceHexPattern(data, search, replace);
        } else {
            data = HexUtils.replaceAscii(data, search, replace == null ? "" : replace);
        }
        data = fitLocked(data);
        lastEdit = EditSource.DUMP;
        refreshViews();
        changeListener.accept(data);
    }

    public void clear() {
        lockedLength = -1;
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
