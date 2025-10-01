document.addEventListener('DOMContentLoaded', () => {
    const cards = document.querySelectorAll('.option-card');

    cards.forEach(card => {
        card.addEventListener('click', () => {
            cards.forEach(c => c.classList.remove('active'));
            card.classList.add('active');
        });
    });
});