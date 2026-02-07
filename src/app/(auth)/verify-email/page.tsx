"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { verifyEmail } from "@/actions/auth.actions";
import { AuthCard } from "@/components/auth/auth-card";
import { FormError } from "@/components/auth/form-error";
import { FormSuccess } from "@/components/auth/form-success";
import { Button } from "@/components/ui/button";
import Link from "next/link";
import { Loader2 } from "lucide-react";

function VerifyEmailForm() {
  const searchParams = useSearchParams();
  const token = searchParams.get("token");

  const [error, setError] = useState<string | undefined>();
  const [success, setSuccess] = useState<string | undefined>();

  useEffect(() => {
    if (!token) return;

    let isMounted = true;

    const verify = async () => {
      try {
        const result = await verifyEmail(token);

        if (!isMounted) return;

        if (result.error) {
          setError(result.error);
        }

        if (result.success && result.message) {
          setSuccess(result.message);
        }
      } catch {
        if (isMounted) {
          setError("Something went wrong!");
        }
      }
    };

    void verify();

    return () => {
      isMounted = false;
    };
  }, [token]);

  const displayError = error || (!token ? "Missing token!" : undefined);

  return (
    <AuthCard
      title="Email Verification"
      description="Confirming your email address"
    >
      <div className="flex flex-col items-center space-y-4">
        {!success && !displayError && (
          <div className="flex items-center space-x-2">
            <Loader2 className="h-6 w-6 animate-spin text-primary" />
            <span className="text-sm text-muted-foreground">
              Verifying your email...
            </span>
          </div>
        )}

        <FormError message={displayError} />
        <FormSuccess message={success} />

        {(success || displayError) && (
          <Link href="/login" className="w-full">
            <Button className="w-full">Back to login</Button>
          </Link>
        )}
      </div>
    </AuthCard>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense
      fallback={
        <div className="flex justify-center">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      }
    >
      <VerifyEmailForm />
    </Suspense>
  );
}
