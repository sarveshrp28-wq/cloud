const terminalShell = document.getElementById('terminal-shell');
const terminalLines = [
  'Initializing neural interface...',
  'Loading vector embeddings...',
  'Syncing knowledge stream...',
  'Establishing secure inference channel...',
  'Optimizing prompt pathways...'
];
let currentLine = 0;

function appendTerminalLine(text, delay = 0) {
  const line = document.createElement('div');
  line.className = 'terminal-line';
  line.textContent = text;
  line.style.opacity = '0';
  terminalShell.appendChild(line);

  setTimeout(() => {
    line.style.transition = 'opacity 0.35s ease';
    line.style.opacity = '1';
  }, delay);
}

function playTerminalSequence() {
  terminalShell.innerHTML = '';
  terminalLines.forEach((text, index) => {
    appendTerminalLine(text, index * 420);
  });
}

function fadeInSection(section) {
  const observer = new IntersectionObserver(
    entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.22 }
  );

  observer.observe(section);
}

document.addEventListener('DOMContentLoaded', () => {
  playTerminalSequence();
  setInterval(() => {
    currentLine = (currentLine + 1) % terminalLines.length;
    const lines = Array.from(terminalShell.querySelectorAll('.terminal-line'));
    lines.forEach((line, index) => {
      line.classList.toggle('current', index === currentLine);
    });
  }, 2800);

  const animatedSections = document.querySelectorAll('.section-block, .glass-card, .hero-copy, .hero-visual');
  animatedSections.forEach(section => fadeInSection(section));
});
