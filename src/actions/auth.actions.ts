"use server";

import { signIn, signOut } from "@/lib/auth";
import { db } from "@/lib/db";
import {
  LoginSchema,
  RegisterSchema,
  ResetPasswordSchema,
  NewPasswordSchema,
  type LoginInput,
  type RegisterInput,
} from "@/lib/validation";
import { AuthError } from "next-auth";
import bcrypt from "bcryptjs";
import { generateToken } from "@/lib/utils";
import { getUserByEmail } from "./user.actions";
import type { ActionResponse } from "@/types";

export async function login(
  values: LoginInput,
  callbackUrl?: string | null,
): Promise<ActionResponse> {
  const validatedFields = LoginSchema.safeParse(values);

  if (!validatedFields.success) {
    return { success: false, error: "Invalid fields!" };
  }

  const { email, password, code } = validatedFields.data;

  const existingUser = await getUserByEmail(email);

  if (!existingUser || !existingUser.email || !existingUser.password) {
    return { success: false, error: "Invalid credentials!" };
  }

  if (!existingUser.isActive) {
    return { success: false, error: "Account is disabled!" };
  }

  if (!existingUser.emailVerified) {
    const verificationToken = await generateVerificationToken(
      existingUser.email,
    );
    return { success: true, message: "Confirmation email sent!" };
  }

  if (existingUser.isTwoFactorEnabled && existingUser.email) {
    if (code) {
      const twoFactorToken = await getTwoFactorTokenByEmail(existingUser.email);

      if (!twoFactorToken || twoFactorToken.token !== code) {
        return { success: false, error: "Invalid code!" };
      }

      const hasExpired = new Date(twoFactorToken.expires) < new Date();

      if (hasExpired) {
        return { success: false, error: "Code expired!" };
      }

      await db.twoFactorToken.delete({
        where: { id: twoFactorToken.id },
      });

      const existingConfirmation = await getTwoFactorConfirmationByUserId(
        existingUser.id,
      );

      if (existingConfirmation) {
        await db.twoFactorConfirmation.delete({
          where: { id: existingConfirmation.id },
        });
      }

      await db.twoFactorConfirmation.create({
        data: { userId: existingUser.id },
      });
    } else {
      const twoFactorToken = await generateTwoFactorToken(existingUser.email);
      return { success: true, data: { twoFactor: true } as any };
    }
  }

  try {
    await signIn("credentials", {
      email,
      password,
      redirectTo: callbackUrl || "/dashboard",
    });

    return { success: true };
  } catch (error) {
    if (error instanceof AuthError) {
      switch (error.type) {
        case "CredentialsSignin":
          return { success: false, error: "Invalid credentials!" };
        default:
          return { success: false, error: "Something went wrong!" };
      }
    }

    throw error;
  }
}

export async function register(values: RegisterInput): Promise<ActionResponse> {
  const validatedFields = RegisterSchema.safeParse(values);

  if (!validatedFields.success) {
    return { success: false, error: "Invalid fields!" };
  }

  const { email, password, name } = validatedFields.data;

  const existingUser = await getUserByEmail(email);

  if (existingUser) {
    return { success: false, error: "Email already in use!" };
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  await db.user.create({
    data: {
      name,
      email,
      password: hashedPassword,
    },
  });

  const verificationToken = await generateVerificationToken(email);

  // Send verification email here
  // await sendVerificationEmail(verificationToken.email, verificationToken.token);

  return { success: true, message: "Confirmation email sent!" };
}

export async function logout(): Promise<void> {
  await signOut({ redirectTo: "/login" });
}

export async function signInWithGoogle(callbackUrl?: string): Promise<void> {
  await signIn("google", { redirectTo: callbackUrl || "/dashboard" });
}

export async function signInWithGithub(callbackUrl?: string): Promise<void> {
  await signIn("github", { redirectTo: callbackUrl || "/dashboard" });
}

export async function generateVerificationToken(email: string) {
  const token = generateToken();
  const expires = new Date(new Date().getTime() + 3600 * 1000);

  const existingToken = await getVerificationTokenByEmail(email);

  if (existingToken) {
    await db.verificationToken.delete({
      where: { id: existingToken.id },
    });
  }

  const verificationToken = await db.verificationToken.create({
    data: {
      email,
      token,
      expires,
    },
  });

  return verificationToken;
}

export async function generatePasswordResetToken(email: string) {
  const token = generateToken();
  const expires = new Date(new Date().getTime() + 3600 * 1000);

  const existingToken = await getPasswordResetTokenByEmail(email);

  if (existingToken) {
    await db.passwordResetToken.delete({
      where: { id: existingToken.id },
    });
  }

  const passwordResetToken = await db.passwordResetToken.create({
    data: {
      email,
      token,
      expires,
    },
  });

  return passwordResetToken;
}

export async function generateTwoFactorToken(email: string) {
  const token = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = new Date(new Date().getTime() + 5 * 60 * 1000);

  const existingToken = await getTwoFactorTokenByEmail(email);

  if (existingToken) {
    await db.twoFactorToken.delete({
      where: { id: existingToken.id },
    });
  }

  const twoFactorToken = await db.twoFactorToken.create({
    data: {
      email,
      token,
      expires,
    },
  });

  return twoFactorToken;
}

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

export async function verifyEmail(token: string): Promise<ActionResponse> {
  const existingToken = await db.verificationToken.findUnique({
    where: { token },
  });

  if (!existingToken) {
    return { success: false, error: "Token does not exist!" };
  }

  const hasExpired = new Date(existingToken.expires) < new Date();

  if (hasExpired) {
    return { success: false, error: "Token has expired!" };
  }

  const existingUser = await getUserByEmail(existingToken.email);

  if (!existingUser) {
    return { success: false, error: "Email does not exist!" };
  }

  await db.user.update({
    where: { id: existingUser.id },
    data: {
      emailVerified: new Date(),
      email: existingToken.email,
    },
  });

  await db.verificationToken.delete({
    where: { id: existingToken.id },
  });

  return { success: true, message: "Email verified!" };
}

export async function resetPassword(values: {
  email: string;
}): Promise<ActionResponse> {
  const validatedFields = ResetPasswordSchema.safeParse(values);

  if (!validatedFields.success) {
    return { success: false, error: "Invalid email!" };
  }

  const { email } = validatedFields.data;

  const existingUser = await getUserByEmail(email);

  if (!existingUser) {
    return { success: false, error: "Email not found!" };
  }

  const passwordResetToken = await generatePasswordResetToken(email);

  return { success: true, message: "Reset email sent!" };
}

export async function newPassword(
  values: { password: string; confirmPassword: string },
  token?: string | null,
): Promise<ActionResponse> {
  if (!token) {
    return { success: false, error: "Missing token!" };
  }

  const validatedFields = NewPasswordSchema.safeParse(values);

  if (!validatedFields.success) {
    return { success: false, error: "Invalid fields!" };
  }

  const { password } = validatedFields.data;

  const existingToken = await db.passwordResetToken.findUnique({
    where: { token },
  });

  if (!existingToken) {
    return { success: false, error: "Invalid token!" };
  }

  const hasExpired = new Date(existingToken.expires) < new Date();

  if (hasExpired) {
    return { success: false, error: "Token has expired!" };
  }

  const existingUser = await getUserByEmail(existingToken.email);

  if (!existingUser) {
    return { success: false, error: "Email does not exist!" };
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  await db.user.update({
    where: { id: existingUser.id },
    data: { password: hashedPassword },
  });

  await db.passwordResetToken.delete({
    where: { id: existingToken.id },
  });

  return { success: true, message: "Password updated!" };
}
