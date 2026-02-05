export type Step = 'home' | 'enrollment' | 'authentication' | 'verification';

export interface StepInfo {
  id: Step;
  label: string;
  number: number;
}

export const STEPS: StepInfo[] = [
  { id: 'home', label: 'Home', number: 0 },
  { id: 'enrollment', label: 'Enrollment', number: 1 },
  { id: 'authentication', label: 'Authentication', number: 2 },
  { id: 'verification', label: 'Verification', number: 3 },
];

export function renderNavigation(
  currentStep: Step,
  completedSteps: Set<Step>,
  _onNavigate: (step: Step) => void
): string {
  const currentIndex = STEPS.findIndex(s => s.id === currentStep);

  return `
    <nav class="nav" id="main-nav">
      ${STEPS.filter(s => s.number > 0).map(step => {
        const isActive = step.id === currentStep;
        const isCompleted = completedSteps.has(step.id);
        const isAccessible = step.number <= currentIndex || isCompleted;

        let className = 'nav-item';
        if (isActive) className += ' active';
        else if (isCompleted) className += ' completed';

        return `
          <button
            class="${className}"
            data-step="${step.id}"
            ${!isAccessible ? 'disabled' : ''}
          >
            <span class="step-num">${step.number}</span>
            ${step.label}
          </button>
        `;
      }).join('')}
    </nav>
  `;
}

export function attachNavigationHandlers(onNavigate: (step: Step) => void): void {
  document.querySelectorAll('.nav-item[data-step]').forEach(btn => {
    btn.addEventListener('click', () => {
      const step = btn.getAttribute('data-step') as Step;
      if (step) onNavigate(step);
    });
  });
}
