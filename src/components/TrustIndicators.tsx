import { Clock, FileCheck2, UserX } from 'lucide-react';
import { useTranslation } from '../i18n/index.tsx';

export function TrustIndicators() {
  const { t } = useTranslation();

  const items = [
    {
      Icon: UserX,
      title: t.trust.noAccountTitle,
      desc: t.trust.noAccountDesc,
    },
    {
      Icon: Clock,
      title: t.trust.tempProcessTitle,
      desc: t.trust.tempProcessDesc,
    },
    {
      Icon: FileCheck2,
      title: t.trust.clearReportsTitle,
      desc: t.trust.clearReportsDesc,
    },
  ];

  return (
    <section aria-label="Trust and privacy guarantees" className="mt-8 space-y-6">
      <div className="grid gap-4 sm:grid-cols-3">
        {items.map(({ Icon, title, desc }) => (
          <div
            key={title}
            className="rounded-xl border border-slate-200 bg-white p-5"
          >
            <Icon className="h-5 w-5 text-slate-700" aria-hidden="true" />
            <h2 className="mt-3 text-sm font-semibold text-slate-900">{title}</h2>
            <p className="mt-1.5 text-xs leading-relaxed text-slate-600">{desc}</p>
          </div>
        ))}
      </div>

      <p className="text-center text-xs leading-relaxed text-slate-500">
        {t.trust.disclaimer}
      </p>
    </section>
  );
}
