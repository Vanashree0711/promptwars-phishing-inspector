'use strict';

/**
 * create-sample-pdf.js
 * Generates sample PDF offer letters for testing the Phishing Inspector application.
 * - sample_scam_offer_letter.pdf (Contains phishing payment traps & fake appointment red flags)
 * - sample_legit_offer_letter.pdf (Clean standard job offer letter)
 */

const fs = require('fs');
const path = require('path');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');

async function generatePdfs() {
  const outputDir = path.join(__dirname, 'public', 'downloads');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // -------------------------------------------------------------
  // 1. SCAM OFFER LETTER PDF
  // -------------------------------------------------------------
  const scamDoc = await PDFDocument.create();
  const scamFont = await scamDoc.embedFont(StandardFonts.Helvetica);
  const scamBoldFont = await scamDoc.embedFont(StandardFonts.HelveticaBold);
  const scamPage = scamDoc.addPage([612, 792]); // Letter size

  const { width, height } = scamPage.getSize();

  // Header Banner
  scamPage.drawRectangle({
    x: 0,
    y: height - 80,
    width: width,
    height: 80,
    color: rgb(0.08, 0.12, 0.25),
  });

  scamPage.drawText('APEX GLOBAL TECHNOLOGIES LTD.', {
    x: 40,
    y: height - 50,
    size: 20,
    font: scamBoldFont,
    color: rgb(0.95, 0.95, 1.0),
  });

  scamPage.drawText('Official Appointment & Onboarding Notice', {
    x: 40,
    y: height - 70,
    size: 11,
    font: scamFont,
    color: rgb(0.7, 0.8, 1.0),
  });

  // Body content
  let y = height - 120;
  const margin = 40;

  scamPage.drawText('CONFIDENTIAL APPOINTMENT & JOB OFFER LETTER', {
    x: margin,
    y: y,
    size: 14,
    font: scamBoldFont,
    color: rgb(0.1, 0.1, 0.1),
  });
  y -= 25;

  scamPage.drawText(`Date: September 22, 2026`, { x: margin, y: y, size: 10, font: scamFont });
  y -= 15;
  scamPage.drawText(`Candidate: Alex Morgan`, { x: margin, y: y, size: 10, font: scamFont });
  y -= 25;

  const bodyLines = [
    'Dear Alex Morgan,',
    '',
    'We are delighted to offer you the full-time remote position of Senior Cloud Solutions Engineer',
    'at Apex Global Technologies Ltd. Your monthly starting compensation will be $9,200 USD, payable bi-weekly.',
    '',
    'URGENT MANDATORY EQUIPMENT SECURITY DEPOSIT REQUIREMENT:',
    'To finalize your official onboarding package and ship your company-issued Apple MacBook Pro M3,',
    'dual 4K monitors, and encrypted workstation hardware, you are required to submit a fully refundable',
    'equipment security deposit of $450 USD prior to your official start date.',
    '',
    'PAYMENT INSTRUCTIONS FOR EQUIPMENT DEPOSIT:',
    'Please send the $450 security deposit via Zelle, CashApp, or Apple Gift Card to our HR Finance Manager',
    'at onboarding-finance@apex-globaltech-jobs.com within 24 hours of signing this offer letter.',
    'This deposit is 100% refundable and will be added directly to your first paycheck.',
    '',
    'Failure to send the deposit within 24 hours will result in immediate cancellation of your appointment.',
    '',
    'Sincerely,',
    'HR Onboarding & Logistics Department',
    'Apex Global Technologies Ltd.'
  ];

  for (const line of bodyLines) {
    const isBold = line.startsWith('URGENT') || line.startsWith('PAYMENT') || line.startsWith('Dear') || line.startsWith('CONFIDENTIAL');
    scamPage.drawText(line, {
      x: margin,
      y: y,
      size: isBold ? 11 : 10,
      font: isBold ? scamBoldFont : scamFont,
      color: isBold && line.startsWith('URGENT') ? rgb(0.85, 0.1, 0.1) : rgb(0.15, 0.15, 0.15),
    });
    y -= 18;
  }

  const scamPdfBytes = await scamDoc.save();
  const scamPath = path.join(outputDir, 'sample_scam_offer_letter.pdf');
  fs.writeFileSync(scamPath, scamPdfBytes);
  console.log(`[SamplePDF] Generated Scam PDF at ${scamPath}`);

  // -------------------------------------------------------------
  // 2. LEGIT OFFER LETTER PDF
  // -------------------------------------------------------------
  const legitDoc = await PDFDocument.create();
  const legitFont = await legitDoc.embedFont(StandardFonts.Helvetica);
  const legitBoldFont = await legitDoc.embedFont(StandardFonts.HelveticaBold);
  const legitPage = legitDoc.addPage([612, 792]);

  // Header Banner
  legitPage.drawRectangle({
    x: 0,
    y: height - 80,
    width: width,
    height: 80,
    color: rgb(0.1, 0.4, 0.3),
  });

  legitPage.drawText('VERITAS HEALTH SYSTEMS', {
    x: 40,
    y: height - 50,
    size: 20,
    font: legitBoldFont,
    color: rgb(1, 1, 1),
  });

  legitPage.drawText('100 Healthcare Way, Suite 400 • Austin, TX 78701', {
    x: 40,
    y: height - 70,
    size: 10,
    font: legitFont,
    color: rgb(0.85, 0.95, 0.9),
  });

  y = height - 120;

  legitPage.drawText('EMPLOYMENT OFFER LETTER', {
    x: margin,
    y: y,
    size: 14,
    font: legitBoldFont,
    color: rgb(0.1, 0.1, 0.1),
  });
  y -= 25;

  legitPage.drawText(`Date: September 22, 2026`, { x: margin, y: y, size: 10, font: legitFont });
  y -= 15;
  legitPage.drawText(`To: Sarah Connor`, { x: margin, y: y, size: 10, font: legitFont });
  y -= 25;

  const legitBodyLines = [
    'Dear Sarah,',
    '',
    'On behalf of Veritas Health Systems, I am thrilled to offer you the position of Senior Systems Analyst.',
    'We were very impressed by your qualifications and experience during the interview process.',
    '',
    'Compensation and Benefits:',
    '• Annual Base Salary: $115,000 USD, payable bi-weekly in accordance with standard payroll schedules.',
    '• Health Benefits: Full medical, dental, and vision coverage starting on your first day of employment.',
    '• 401(k) Plan: Company match up to 5% with immediate vesting.',
    '• Paid Time Off: 20 days accrued PTO per calendar year plus 10 company holidays.',
    '',
    'Equipment & Setup:',
    'All required hardware and software will be provided directly by our IT Department upon your arrival',
    'at our Austin office on your start date, or shipped directly to your verified home address at zero cost to you.',
    'Veritas Health Systems never requests any payments or security deposits from candidates.',
    '',
    'Please review and sign this offer letter within 5 business days to accept.',
    '',
    'Sincerely,',
    'Human Resources Department',
    'Veritas Health Systems Inc.'
  ];

  for (const line of legitBodyLines) {
    const isBold = line.includes(':') && !line.includes('Date:');
    legitPage.drawText(line, {
      x: margin,
      y: y,
      size: isBold ? 11 : 10,
      font: isBold ? legitBoldFont : legitFont,
      color: rgb(0.15, 0.15, 0.15),
    });
    y -= 18;
  }

  const legitPdfBytes = await legitDoc.save();
  const legitPath = path.join(outputDir, 'sample_legit_offer_letter.pdf');
  fs.writeFileSync(legitPath, legitPdfBytes);
  console.log(`[SamplePDF] Generated Legit PDF at ${legitPath}`);
}

generatePdfs().catch(err => {
  console.error('[SamplePDF] Error generating PDFs:', err);
  process.exit(1);
});
