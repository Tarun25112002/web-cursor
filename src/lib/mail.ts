import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);
const domain = process.env.NEXT_PUBLIC_APP_URL;

// ============================================
// SEND 2FA CODE EMAIL ✅
// ============================================
export async function sendTwoFactorEmail(email: string, token: string) {
  try {
    await resend.emails.send({
      from: "Auth App <onboarding@resend.dev>", // Use your verified domain in production
      to: email,
      subject: "🔐 Your Two-Factor Authentication Code",
      html: `
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>2FA Code</title>
          </head>
          <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f4f4f5;">
            <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
              <div style="background-color: white; border-radius: 12px; padding: 40px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                
                <!-- Logo/Header -->
                <div style="text-align: center; margin-bottom: 30px;">
                  <div style="width: 60px; height: 60px; background-color: #2563eb; border-radius: 12px; margin: 0 auto 16px; display: flex; align-items: center; justify-content: center;">
                    <span style="color: white; font-size: 24px; font-weight: bold;">🔐</span>
                  </div>
                  <h1 style="color: #1f2937; font-size: 24px; margin: 0;">Two-Factor Authentication</h1>
                </div>

                <!-- Message -->
                <p style="color: #4b5563; font-size: 16px; line-height: 1.6; text-align: center; margin-bottom: 30px;">
                  You're trying to sign in to your account. Use the code below to complete the login process.
                </p>

                <!-- Code Box -->
                <div style="background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); border-radius: 12px; padding: 30px; text-align: center; margin-bottom: 30px;">
                  <p style="color: rgba(255,255,255,0.8); font-size: 14px; margin: 0 0 10px 0; text-transform: uppercase; letter-spacing: 2px;">
                    Your verification code
                  </p>
                  <div style="font-size: 42px; font-weight: bold; color: white; letter-spacing: 12px; font-family: 'Courier New', monospace;">
                    ${token}
                  </div>
                </div>

                <!-- Warning -->
                <div style="background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 16px; border-radius: 0 8px 8px 0; margin-bottom: 30px;">
                  <p style="color: #92400e; font-size: 14px; margin: 0;">
                    ⚠️ This code will expire in <strong>5 minutes</strong>. Never share this code with anyone.
                  </p>
                </div>

                <!-- Security Note -->
                <p style="color: #6b7280; font-size: 14px; line-height: 1.6; text-align: center;">
                  If you didn't request this code, please ignore this email or contact support if you believe your account has been compromised.
                </p>

              </div>

              <!-- Footer -->
              <div style="text-align: center; margin-top: 30px;">
                <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                  © ${new Date().getFullYear()} Auth App. All rights reserved.
                </p>
              </div>
            </div>
          </body>
        </html>
      `,
    });

    console.log(`✅ 2FA code sent to ${email}`);
    return { success: true };
  } catch (error) {
    console.error("Failed to send 2FA email:", error);
    return { success: false, error };
  }
}

// ============================================
// SEND VERIFICATION EMAIL
// ============================================
export async function sendVerificationEmail(email: string, token: string) {
  const confirmLink = `${domain}/verify-email?token=${token}`;

  try {
    await resend.emails.send({
      from: "Auth App <onboarding@resend.dev>",
      to: email,
      subject: "✉️ Verify Your Email Address",
      html: `
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
          </head>
          <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f4f4f5;">
            <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
              <div style="background-color: white; border-radius: 12px; padding: 40px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                
                <div style="text-align: center; margin-bottom: 30px;">
                  <h1 style="color: #1f2937; font-size: 24px; margin: 0;">Verify Your Email</h1>
                </div>

                <p style="color: #4b5563; font-size: 16px; line-height: 1.6; text-align: center; margin-bottom: 30px;">
                  Thank you for registering! Please click the button below to verify your email address.
                </p>

                <div style="text-align: center; margin-bottom: 30px;">
                  <a href="${confirmLink}" 
                     style="display: inline-block; padding: 16px 32px; background-color: #2563eb; 
                            color: white; text-decoration: none; border-radius: 8px; font-weight: 600;
                            font-size: 16px;">
                    Verify Email Address
                  </a>
                </div>

                <p style="color: #6b7280; font-size: 14px; text-align: center;">
                  This link will expire in 1 hour.
                </p>

                <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">

                <p style="color: #9ca3af; font-size: 12px; text-align: center;">
                  If you didn't create an account, you can safely ignore this email.
                </p>
              </div>
            </div>
          </body>
        </html>
      `,
    });

    console.log(`✅ Verification email sent to ${email}`);
    return { success: true };
  } catch (error) {
    console.error("Failed to send verification email:", error);
    return { success: false, error };
  }
}

// ============================================
// SEND PASSWORD RESET EMAIL
// ============================================
export async function sendPasswordResetEmail(email: string, token: string) {
  const resetLink = `${domain}/new-password?token=${token}`;

  try {
    await resend.emails.send({
      from: "Auth App <onboarding@resend.dev>",
      to: email,
      subject: "🔑 Reset Your Password",
      html: `
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
          </head>
          <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f4f4f5;">
            <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
              <div style="background-color: white; border-radius: 12px; padding: 40px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                
                <div style="text-align: center; margin-bottom: 30px;">
                  <h1 style="color: #1f2937; font-size: 24px; margin: 0;">Reset Your Password</h1>
                </div>

                <p style="color: #4b5563; font-size: 16px; line-height: 1.6; text-align: center; margin-bottom: 30px;">
                  You requested to reset your password. Click the button below to create a new password.
                </p>

                <div style="text-align: center; margin-bottom: 30px;">
                  <a href="${resetLink}" 
                     style="display: inline-block; padding: 16px 32px; background-color: #2563eb; 
                            color: white; text-decoration: none; border-radius: 8px; font-weight: 600;
                            font-size: 16px;">
                    Reset Password
                  </a>
                </div>

                <p style="color: #6b7280; font-size: 14px; text-align: center;">
                  This link will expire in 1 hour.
                </p>

                <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">

                <p style="color: #9ca3af; font-size: 12px; text-align: center;">
                  If you didn't request a password reset, you can safely ignore this email.
                </p>
              </div>
            </div>
          </body>
        </html>
      `,
    });

    console.log(`✅ Password reset email sent to ${email}`);
    return { success: true };
  } catch (error) {
    console.error("Failed to send password reset email:", error);
    return { success: false, error };
  }
}
