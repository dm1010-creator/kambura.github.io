// Hero animation

const heroImg=document.getElementById("heroBgImg");

if(heroImg){

heroImg.addEventListener("load",()=>{

heroImg.classList.add("loaded");

});

if(heroImg.complete){

heroImg.classList.add("loaded");

}

}

// Scroll reveal

const revealEls=document.querySelectorAll(
".reveal,.reveal-left,.reveal-right"
);

const observer=new IntersectionObserver(entries=>{

entries.forEach((entry,index)=>{

if(entry.isIntersecting){

setTimeout(()=>{

entry.target.classList.add("visible");

},index*80);

observer.unobserve(entry.target);

}

});

},{
threshold:.12,
rootMargin:"0px 0px -40px 0px"
});

revealEls.forEach(el=>observer.observe(el));

// Order form

function handleSubmit(e){

e.preventDefault();

const btn=document.getElementById("submitBtn");

const input=document.getElementById("emailInput");

btn.textContent="Sent ✓";
btn.disabled=true;
btn.classList.add("sent");

input.value="";

}

// Parallax

const hero=document.querySelector(".hero-bg img");

if(hero){

window.addEventListener("scroll",()=>{

const y=window.scrollY;

if(y<window.innerHeight){

hero.style.transform=`scale(1) translateY(${y*.18}px)`;

}

},{passive:true});

}
