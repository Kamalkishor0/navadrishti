import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import crypto from 'crypto';
import { createServerClient } from '@/lib/supabase';

const prepareEmailOtpSchema = z.object({
  email: z.string().email('Invalid email address')
});

const PREPARE_RATE_LIMIT_MS = 60 * 1000;
const prepareRateLimitStore = new Map<string, number>();

const normalizeEmail = (value: string) => value.trim().toLowerCase();

const isAlreadyRegisteredError = (error: unknown) => {
  if (!error || typeof error !== 'object') {
    return false;
  }

  const maybeError = error as {
    message?: string;
    code?: string;
    status?: number;
    name?: string;
  };

  const normalizedMessage = (maybeError.message || '').toLowerCase();
  const normalizedCode = (maybeError.code || '').toLowerCase();
  const status = maybeError.status;

  return (
    normalizedMessage.includes('already registered') ||
    normalizedMessage.includes('already been registered') ||
    normalizedMessage.includes('already exists') ||
    normalizedMessage.includes('duplicate') ||
    normalizedMessage.includes('user already registered') ||
    normalizedMessage.includes('user already exists') ||
    normalizedCode.includes('user_already_exists') ||
    normalizedCode.includes('email_exists') ||
    status === 409 ||
    status === 422
  );
};

const cleanupRateLimitStore = () => {
  const now = Date.now();
  for (const [email, timestamp] of prepareRateLimitStore.entries()) {
    if (now - timestamp > PREPARE_RATE_LIMIT_MS * 2) {
      prepareRateLimitStore.delete(email);
    }
  }
};

export async function POST(req: NextRequest) {
  try {
    if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
      return NextResponse.json(
        {
          error:
            process.env.NODE_ENV === 'development'
              ? 'Failed to prepare email OTP session: SUPABASE_SERVICE_ROLE_KEY is not set'
              : 'Failed to prepare email OTP session'
        },
        { status: 500 }
      );
    }

    const body = await req.json();
    const validationResult = prepareEmailOtpSchema.safeParse(body);

    if (!validationResult.success) {
      return NextResponse.json({ error: validationResult.error.issues[0]?.message || 'Invalid email address' }, { status: 400 });
    }

    const email = normalizeEmail(validationResult.data.email);
    cleanupRateLimitStore();

    const lastPreparedAt = prepareRateLimitStore.get(email);
    if (lastPreparedAt && Date.now() - lastPreparedAt < PREPARE_RATE_LIMIT_MS) {
      const retryAfterSeconds = Math.ceil((PREPARE_RATE_LIMIT_MS - (Date.now() - lastPreparedAt)) / 1000);
      return NextResponse.json({ error: `Please wait ${retryAfterSeconds}s before requesting another email OTP` }, { status: 429 });
    }

    const supabase = createServerClient();

    const { error } = await supabase.auth.admin.createUser({
      email,
      password: crypto.randomBytes(24).toString('base64url'),
      email_confirm: true
    });

    if (error && !isAlreadyRegisteredError(error)) {
      const errorMessage = (error as { message?: string }).message || 'Unknown error';
      console.error('Prepare email OTP error:', {
        message: (error as { message?: string }).message,
        code: (error as { code?: string }).code,
        status: (error as { status?: number }).status,
        name: (error as { name?: string }).name
      });
      return NextResponse.json(
        {
          error:
            process.env.NODE_ENV === 'development'
              ? `Failed to prepare email OTP session: ${errorMessage}`
              : 'Failed to prepare email OTP session'
        },
        { status: 500 }
      );
    }

    prepareRateLimitStore.set(email, Date.now());

    return NextResponse.json({
      prepared: true,
      message: 'Email OTP session prepared'
    });
  } catch (error) {
    console.error('Prepare email OTP unexpected error:', error);
    return NextResponse.json({ error: 'Failed to prepare email OTP session' }, { status: 500 });
  }
}