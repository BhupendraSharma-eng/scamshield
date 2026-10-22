// One-tap demo inputs (subset of demo/samples.json and the Kaggle sets).

export interface Sample {
  label: string;
  scam: boolean;
  sender?: string;
  subject?: string;
  text: string;
}

export const SMS_SAMPLES: Sample[] = [
  { label: "SBI KYC block", scam: true, sender: "VM-SBIINB", text: "Dear SBI customer, your YONO account will be blocked today due to pending KYC. Update PAN immediately: http://sbi-kyc-update.xyz/login" },
  { label: "Electricity cut", scam: true, text: "Dear Consumer, your electricity power will be disconnected tonight at 9.30 pm because your previous month bill was not updated. Please immediately contact our electricity officer 9876543210" },
  { label: "UPI cashback", scam: true, text: "Congratulations! You have received a cashback of Rs 5,000 from PhonePe. Scan the QR and enter your UPI PIN to receive the money in your account." },
  { label: "Hinglish KYC", scam: true, text: "Aapka bank account aaj band ho jayega. KYC update karne ke liye turant is link pe click karein bit.ly/3kycUpd aur OTP batayein" },
  { label: "Digital arrest", scam: true, text: "This is from Mumbai Cyber Police. An FIR has been registered against your Aadhaar for money laundering. Join video call immediately or arrest warrant will be issued." },
  { label: "Bank OTP (real)", scam: false, sender: "AD-HDFCBK", text: "123456 is your OTP for transaction of INR 1,250.00 at AMAZON on HDFC Bank Card XX4521. Valid for 10 mins. Do not share OTP with anyone. -HDFC Bank" },
  { label: "IRCTC PNR (real)", scam: false, sender: "AD-IRCTCI", text: "PNR 4521873690 Train 12951 Dt 25-10-26 Class 3A Chart Prepared. Coach B2 Berth 34. Wish you a happy journey -IRCTC" },
  { label: "Friend chat", scam: false, text: "Bhai kal college aa raha hai kya? Assignment submit karna hai, sir ne deadline Friday di hai." },
];

export const EMAIL_SAMPLES: Sample[] = [
  { label: "HDFC suspended", scam: true, sender: "HDFC Bank <alerts@hdfc-secure.top>", subject: "Urgent: Your HDFC NetBanking access is suspended", text: "Dear Customer, we detected unusual activity on your account. Your NetBanking access has been temporarily suspended. To restore access, verify your identity within 24 hours by clicking the link below. Failure to do so will result in permanent closure.\n\nVerify now: https://hdfc-secure-verify.top/netbanking\n\nHDFC Bank Security Team" },
  { label: "Invoice bank change", scam: true, sender: "Accounts <accounts@vendor-billing.co>", subject: "Updated bank details for invoice #INV-20931", text: "Hi, please note that our company bank account has changed due to an audit. Kindly process the pending payment of Rs 3,45,000 for invoice INV-20931 to the new account below today itself. Please do not call the old number as it is not in service.\n\nAccount: 50100234567812, IFSC: XYZB0001234\n\nRegards, Accounts Team" },
  { label: "Fake job offer", scam: true, sender: "Amazon HR <amazonhr.india@gmail.com>", subject: "Offer Letter - Work From Home Data Entry", text: "Congratulations! You have been selected for the post of Data Entry Executive at Amazon India with a salary of Rs 45,000 per month. To confirm your joining, pay the refundable registration fee of Rs 2,500 via UPI to amazonhr@ybl within 6 hours." },
  { label: "Amazon shipped (real)", scam: false, sender: "Amazon.in <shipment-tracking@amazon.in>", subject: "Your Amazon.in order #403-1234567-8901234 has shipped", text: "Hello, your package with Logitech M331 Silent Mouse has shipped and is expected to arrive on Thursday, 24 October. You can track your package in Your Orders on Amazon.in. Thank you for shopping with us." },
  { label: "Team notes (real)", scam: false, sender: "Priya <priya@acme.dev>", subject: "Notes from today's design review", text: "Hi team, thanks for joining the design review. Action items: Priya to update the API spec by Monday, Rahul to share load-test results, and I'll set up the follow-up meeting next week." },
];

export const URL_SAMPLES: Sample[] = [
  { label: "sbi-kyc-update.xyz", scam: true, text: "http://sbi-kyc-update.xyz/login" },
  { label: "Punycode PhonePe", scam: true, text: "https://xn--phonpe-0ra.com/login" },
  { label: "amaz0n-in.com", scam: true, text: "https://www.amaz0n-in.com/gift-card/claim" },
  { label: "IP login page", scam: true, text: "http://192.168.43.12/icici/login.php" },
  { label: "appIe-id-verify", scam: true, text: "http://support.appIe-id-verify.cc/verify" },
  { label: "onlinesbi.sbi (real)", scam: false, text: "https://www.onlinesbi.sbi/" },
  { label: "incometax.gov.in (real)", scam: false, text: "https://www.incometax.gov.in/iec/foportal/" },
];
