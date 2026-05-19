// Compose the full PQID whitepaper into a single .docx.
const fs = require("fs");
const H = require("./wp_helpers");
const {
  Document, Packer, Paragraph, TextRun, AlignmentType, LevelFormat,
  PageNumber, Header, Footer, HeadingLevel,
  COLORS,
} = H;

const { buildCoverAndIntro }                  = require("./wp_section1_intro");
const { buildWhy, buildSpec }                 = require("./wp_section2_why_spec");
const { buildRationale, buildWhen }           = require("./wp_section3_rationale_when");
const { buildHow, buildSecurity, buildDistributed } = require("./wp_section4_how_security");
const { buildComparison, buildBenchmarks, buildMigration, buildScaleAndAI, buildFuture, buildAppendices } =
  require("./wp_section5_compare_bench");

// ── Compose all sections in order ──────────────────────────────────────────
const children = [
  ...buildCoverAndIntro(),
  ...buildWhy(),
  ...buildSpec(),
  ...buildRationale(),
  ...buildWhen(),
  ...buildHow(),
  ...buildSecurity(),
  ...buildDistributed(),
  ...buildComparison(),
  ...buildBenchmarks(),
  ...buildMigration(),
  ...buildScaleAndAI(),
  ...buildFuture(),
  ...buildAppendices(),
];

// ── Build document ────────────────────────────────────────────────────────
const doc = new Document({
  creator: "PQID Working Group",
  title: "PQID — Post-Quantum Identifier",
  description: "Specification, rationale, and reference implementations for the PQID identifier format",

  styles: {
    default: {
      document: { run: { font: "Arial", size: 22 } }, // 11pt body
    },
    paragraphStyles: [
      {
        id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal",
        quickFormat: true,
        run: { size: 40, bold: true, font: "Arial", color: COLORS.primary },
        paragraph: { spacing: { before: 480, after: 240 }, outlineLevel: 0 },
      },
      {
        id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal",
        quickFormat: true,
        run: { size: 30, bold: true, font: "Arial", color: COLORS.accent },
        paragraph: { spacing: { before: 360, after: 180 }, outlineLevel: 1 },
      },
      {
        id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal",
        quickFormat: true,
        run: { size: 24, bold: true, font: "Arial", color: COLORS.primary },
        paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 2 },
      },
    ],
  },

  numbering: {
    config: [
      {
        reference: "bullets",
        levels: [
          { level: 0, format: LevelFormat.BULLET, text: "•",
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } } },
        ],
      },
      {
        reference: "numbers",
        levels: [
          { level: 0, format: LevelFormat.DECIMAL, text: "%1.",
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } } },
        ],
      },
    ],
  },

  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 },        // US Letter
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
      },
    },
    headers: {
      default: new Header({
        children: [
          new Paragraph({
            alignment: AlignmentType.RIGHT,
            children: [new TextRun({
              text: "PQID — Post-Quantum Identifier",
              size: 18, color: COLORS.muted, italics: true,
            })],
          }),
        ],
      }),
    },
    footers: {
      default: new Footer({
        children: [
          new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new TextRun({ text: "Page ", size: 18, color: COLORS.muted }),
              new TextRun({ children: [PageNumber.CURRENT], size: 18, color: COLORS.muted }),
              new TextRun({ text: " of ", size: 18, color: COLORS.muted }),
              new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 18, color: COLORS.muted }),
            ],
          }),
        ],
      }),
    },
    children,
  }],
});

const OUT = "/home/claude/pqid/docs/PQID_Whitepaper.docx";
Packer.toBuffer(doc).then((buffer) => {
  fs.writeFileSync(OUT, buffer);
  console.log("Wrote:", OUT, "(" + (buffer.length / 1024).toFixed(1) + " KB)");
});
