import bcrypt from "bcrypt";

import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import bcrypt from "bcrypt";
import { z } from "zod";
import { db } from "@vercel/postgres";
import { authConfig } from "./auth.config";
import type { User } from "@/app/lib/definitions";

import { loadEnvConfig } from "@next/env";

const client = await db.connect();

const projectDir = process.cwd();
loadEnvConfig(projectDir);

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user =
      await client.sql<User>`SELECT * FROM users WHERE email=${email}`;
    console.log("User:", user);
    return user.rows[0];
  } catch (error) {
    console.log("Got an error of " + error);
    throw new Error("Failed to fetch user.");
  }
}

export async function main() {
  const user = await getUser("user@nextmail.com");
  const password = "123456";
  const hashedPassword = await bcrypt.hash(password, 10);
  console.log("Hashed password:", hashedPassword);
}

main();
