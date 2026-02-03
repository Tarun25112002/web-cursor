"use server";

import { db } from "@/lib/db";
import { auth } from "@/lib/auth";
import { ProfileSchema, type ProfileInput } from "@/lib/validation";
import type { ActionResponse } from "@/types";
import bcrypt from "bcryptjs";

export async function getUserByEmail(email: string) {
  try {
    return await db.user.findUnique({
      where: { email },
    });
  } catch {
    return null;
  }
}

export async function getUserById(id: string) {
  try {
    return await db.user.findUnique({
      where: { id },
    });
  } catch {
    return null;
  }
}

export async function getCurrentUser() {
  const session = await auth();
  return session?.user;
}

export async function updateProfile(
  values: ProfileInput,
): Promise<ActionResponse> {
  const session = await auth();

  if (!session?.user?.id) {
    return { success: false, error: "Unauthorized" };
  }

  const validatedFields = ProfileSchema.safeParse(values);

  if (!validatedFields.success) {
    return { success: false, error: "Invalid fields!" };
  }

  const dbUser = await getUserById(session.user.id);

  if (!dbUser) {
    return { success: false, error: "User not found!" };
  }

  // Check if user is OAuth - can't change email for OAuth users
  const account = await db.account.findFirst({
    where: { userId: dbUser.id },
  });

  if (account && values.email && values.email !== dbUser.email) {
    return { success: false, error: "Cannot change email for OAuth accounts!" };
  }

  await db.user.update({
    where: { id: dbUser.id },
    data: {
      name: values.name,
      email: values.email,
      isTwoFactorEnabled: values.isTwoFactorEnabled,
    },
  });

  return { success: true, message: "Profile updated!" };
}

export async function changePassword(
  currentPassword: string,
  newPassword: string,
): Promise<ActionResponse> {
  const session = await auth();

  if (!session?.user?.id) {
    return { success: false, error: "Unauthorized" };
  }

  const dbUser = await getUserById(session.user.id);

  if (!dbUser || !dbUser.password) {
    return {
      success: false,
      error: "Cannot change password for OAuth accounts!",
    };
  }

  const isValid = await bcrypt.compare(currentPassword, dbUser.password);

  if (!isValid) {
    return { success: false, error: "Current password is incorrect!" };
  }

  const hashedPassword = await bcrypt.hash(newPassword, 12);

  await db.user.update({
    where: { id: dbUser.id },
    data: { password: hashedPassword },
  });

  return { success: true, message: "Password changed!" };
}

export async function deleteAccount(): Promise<ActionResponse> {
  const session = await auth();

  if (!session?.user?.id) {
    return { success: false, error: "Unauthorized" };
  }

  await db.user.delete({
    where: { id: session.user.id },
  });

  return { success: true, message: "Account deleted!" };
}

export async function getLoginHistory() {
  const session = await auth();

  if (!session?.user?.id) {
    return [];
  }

  return await db.loginHistory.findMany({
    where: { userId: session.user.id },
    orderBy: { createdAt: "desc" },
    take: 10,
  });
}
