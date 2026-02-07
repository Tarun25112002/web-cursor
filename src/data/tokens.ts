import { db } from "@/lib/db";

export async function getVerificationTokenByEmail(email: string) {
  try {
    return await db.verificationToken.findFirst({
      where: { email },
    });
  } catch {
    return null;
  }
}

export async function getPasswordResetTokenByEmail(email: string) {
  try {
    return await db.passwordResetToken.findFirst({
      where: { email },
    });
  } catch {
    return null;
  }
}

export async function getTwoFactorTokenByEmail(email: string) {
  try {
    return await db.twoFactorToken.findFirst({
      where: { email },
    });
  } catch {
    return null;
  }
}

export async function getTwoFactorConfirmationByUserId(userId: string) {
  try {
    return await db.twoFactorConfirmation.findUnique({
      where: { userId },
    });
  } catch {
    return null;
  }
}
