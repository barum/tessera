// TesseraID Whitepaper — Word document generator
// Renders tessera-id/docs/TesseraID_Whitepaper.docx (path resolved relative to build_whitepaper.js)

const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  AlignmentType, LevelFormat, BorderStyle, WidthType, ShadingType,
  HeadingLevel, PageNumber, Header, Footer, PageBreak,
  TabStopType, TabStopPosition,
} = require("docx");

// ────────────────────────────────────────────────────────────────────────────
// Style helpers
// ────────────────────────────────────────────────────────────────────────────

const COLORS = {
  primary: "1B365D",   // dark navy
  accent:  "2E75B6",   // medium blue
  muted:   "5A6473",   // slate
  rule:    "CCCCCC",   // table borders
  codeBg:  "F4F4F6",   // code block background
  warnBg:  "FFF4CE",   // warning panel
  okBg:    "E8F4EA",   // info panel
  black:   "000000",
};

const BORDER = { style: BorderStyle.SINGLE, size: 4, color: COLORS.rule };
const ALL_BORDERS = { top: BORDER, bottom: BORDER, left: BORDER, right: BORDER };

const p = (text, opts = {}) =>
  new Paragraph({
    spacing: { before: 60, after: 80, line: 300 },
    ...opts,
    children: Array.isArray(text)
      ? text
      : [new TextRun({ text, ...(opts.run || {}) })],
  });

const h1 = (text) =>
  new Paragraph({
    heading: HeadingLevel.HEADING_1,
    pageBreakBefore: true,
    children: [new TextRun({ text })],
  });

const h2 = (text) =>
  new Paragraph({
    heading: HeadingLevel.HEADING_2,
    children: [new TextRun({ text })],
  });

const h3 = (text) =>
  new Paragraph({
    heading: HeadingLevel.HEADING_3,
    children: [new TextRun({ text })],
  });

// Code block — monospace, light background, single cell table for the box.
const code = (text) => {
  const lines = text.split("\n");
  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [9360],
    borders: ALL_BORDERS,
    rows: [
      new TableRow({
        children: [
          new TableCell({
            borders: ALL_BORDERS,
            width: { size: 9360, type: WidthType.DXA },
            shading: { fill: COLORS.codeBg, type: ShadingType.CLEAR },
            margins: { top: 120, bottom: 120, left: 180, right: 180 },
            children: lines.map(line =>
              new Paragraph({
                spacing: { before: 0, after: 0, line: 260 },
                children: [new TextRun({ text: line || " ", font: "Consolas", size: 18 })],
              })
            ),
          }),
        ],
      }),
    ],
  });
};

// Callout box (info, warning).
const callout = (label, body, kind = "info") => {
  const fill = kind === "warning" ? COLORS.warnBg : COLORS.okBg;
  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [9360],
    borders: ALL_BORDERS,
    rows: [
      new TableRow({
        children: [
          new TableCell({
            borders: ALL_BORDERS,
            width: { size: 9360, type: WidthType.DXA },
            shading: { fill, type: ShadingType.CLEAR },
            margins: { top: 140, bottom: 140, left: 200, right: 200 },
            children: [
              new Paragraph({
                spacing: { before: 0, after: 80 },
                children: [new TextRun({ text: label, bold: true, size: 22 })],
              }),
              ...body.split("\n\n").map(para =>
                new Paragraph({
                  spacing: { before: 0, after: 80, line: 300 },
                  children: [new TextRun({ text: para, size: 22 })],
                })
              ),
            ],
          }),
        ],
      }),
    ],
  });
};

// Bullet list item using LevelFormat.BULLET (no manual unicode).
const bullet = (text, level = 0) =>
  new Paragraph({
    numbering: { reference: "bullets", level },
    spacing: { before: 40, after: 40, line: 300 },
    children: Array.isArray(text) ? text : [new TextRun({ text })],
  });

// Numbered list item.
const numbered = (text, level = 0) =>
  new Paragraph({
    numbering: { reference: "numbers", level },
    spacing: { before: 40, after: 40, line: 300 },
    children: Array.isArray(text) ? text : [new TextRun({ text })],
  });

// Generic table builder. headers: string[], rows: string[][], widths: int[]
const table = (headers, rows, widths) => {
  const total = widths.reduce((a, b) => a + b, 0);
  const buildCell = (text, w, opts = {}) =>
    new TableCell({
      borders: ALL_BORDERS,
      width: { size: w, type: WidthType.DXA },
      shading: opts.header
        ? { fill: COLORS.primary, type: ShadingType.CLEAR }
        : opts.zebra
        ? { fill: "F7F7F9", type: ShadingType.CLEAR }
        : undefined,
      margins: { top: 80, bottom: 80, left: 120, right: 120 },
      children: [
        new Paragraph({
          spacing: { before: 0, after: 0 },
          children: [
            new TextRun({
              text,
              bold: !!opts.header,
              color: opts.header ? "FFFFFF" : COLORS.black,
              size: opts.header ? 22 : 22,
            }),
          ],
        }),
      ],
    });

  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: widths,
    borders: ALL_BORDERS,
    rows: [
      new TableRow({
        tableHeader: true,
        children: headers.map((h, i) => buildCell(h, widths[i], { header: true })),
      }),
      ...rows.map((row, r) =>
        new TableRow({
          children: row.map((cell, i) =>
            buildCell(cell, widths[i], { zebra: r % 2 === 1 })
          ),
        })
      ),
    ],
  });
};

// Spacer paragraph (small vertical gap).
const spacer = () => new Paragraph({ spacing: { before: 0, after: 60 }, children: [new TextRun("")] });

// Inline code run.
const ic = (text) => new TextRun({ text, font: "Consolas", size: 22 });
const tx = (text, opts = {}) => new TextRun({ text, size: 22, ...opts });
const bold = (text) => new TextRun({ text, bold: true, size: 22 });
const it = (text) => new TextRun({ text, italics: true, size: 22 });

module.exports = {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  AlignmentType, LevelFormat, BorderStyle, WidthType, ShadingType,
  HeadingLevel, PageNumber, Header, Footer, PageBreak,
  TabStopType, TabStopPosition,
  COLORS, BORDER, ALL_BORDERS,
  p, h1, h2, h3, code, callout, bullet, numbered, table, spacer,
  ic, tx, bold, it,
};
