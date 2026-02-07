import NextAuth from "next-auth";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { db } from "./db";
import authConfig from "./auth.config";
import { getUserByEmail, getUserById } from "@/data/user";
import { getTwoFactorConfirmationByUserId } from "@/data/tokens";
import { UserRole } from "@prisma/client";

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut,
} = NextAuth({
  pages: {
    signIn: "/login",
    error: "/error",
  },
  events: {
    async linkAccount({ user }) {
      await db.user.update({
        where: { id: user.id },
        data: { emailVerified: new Date() },
      });
    },
  },
  callbacks: {
    async signIn({ user, account }) {
      if (account?.provider === "credentials") {
        if (!user.id) return false;

        const existingUser = await getUserById(user.id);

        if (!existingUser?.emailVerified) return false;
        if (!existingUser.isActive) return false;

        if (existingUser.isTwoFactorEnabled) {
          const twoFactorConfirmation = await getTwoFactorConfirmationByUserId(
            existingUser.id,
          );

          if (!twoFactorConfirmation) return false;

          await db.twoFactorConfirmation.delete({
            where: { id: twoFactorConfirmation.id },
          });
        }
      } else {
        const existingUser =
          (user.id ? await getUserById(user.id) : null) ??
          (user.email ? await getUserByEmail(user.email) : null);

        if (existingUser && !existingUser.isActive) return false;
      }

      // Login history should never block a successful authentication.
      if (user.id) {
        try {
          await db.loginHistory.create({
            data: {
              userId: user.id,
              success: true,
            },
          });
        } catch (error) {
          console.error("Failed to write login history:", error);
        }
      }

      return true;
    },
    async session({ token, session }) {
      if (token.sub && session.user) {
        session.user.id = token.sub;
      }

      if (token.role && session.user) {
        session.user.role = token.role as UserRole;
      }

      if (session.user) {
        session.user.isTwoFactorEnabled = token.isTwoFactorEnabled as boolean;
        session.user.name = token.name;
        session.user.email = token.email as string;
        session.user.isOAuth = token.isOAuth as boolean;
        session.user.isActive = token.isActive as boolean;
      }

      return session;
    },
    async jwt({ token }) {
      if (!token.sub) return token;

      const existingUser = await getUserById(token.sub);

      if (!existingUser) return token;

      const existingAccount = await db.account.findFirst({
        where: { userId: existingUser.id },
      });

      token.isOAuth = !!existingAccount;
      token.name = existingUser.name;
      token.email = existingUser.email;
      token.role = existingUser.role;
      token.isTwoFactorEnabled = existingUser.isTwoFactorEnabled;
      token.isActive = existingUser.isActive;
      return token;
    },
  },
  adapter: PrismaAdapter(db),
  session: { strategy: "jwt" },
  ...authConfig,
});
