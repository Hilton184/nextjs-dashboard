import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import bcrypt from "bcrypt";
import { z } from "zod";
import { db } from "@vercel/postgres";
import { authConfig } from "./auth.config";
import type { User } from "@/app/lib/definitions";

const client = await db.connect();
async function getUser(email: string): Promise<User | undefined> {
  try {
    const user =
      await client.sql<User>`SELECT * FROM users WHERE email=${email}`;
    console.log("User:", user);
    return user.rows[0];
  } catch (error) {
    throw new Error("Failed to fetch user.");
  }
}

export const { handlers, auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        console.log("Authorizing credentials:", credentials);
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        let user: User | undefined;
        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          try {
            user = await getUser(email);
            console.log("User:", user);
          } catch (error) {
            console.error("Failed to fetch user:", error);
          }
          if (!user) return null;
          const passwordsMatch = await bcrypt.compare(password, user.password);
          if (passwordsMatch) return user;
        }

        return null;
      },
    }),
  ],
});
