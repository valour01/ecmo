/*
 *  linux/arch/arm/mach-versatile/core.c
 *
 *  Copyright (C) 1999 - 2003 ARM Limited
 *  Copyright (C) 2000 Deep Blue Solutions Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <linux/serial_8250.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/sysdev.h>
#include <linux/interrupt.h>
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/cnt32_to_63.h>
#include <linux/io.h>

#include <linux/mtd/physmap.h>
#include <asm/clkdev.h>
#include <asm/system.h>
#include <mach/hardware.h>
#include <asm/irq.h>
#include <asm/hardware/arm_timer.h>
#include <asm/hardware/vic.h>
#include <asm/mach-types.h>

#include <asm/mach/arch.h>
#include <asm/mach/irq.h>
#include <asm/mach/time.h>
#include <asm/mach/map.h>

#include "core.h"
#include "platform.h"
/*
 * All IO addresses are mapped onto VA 0xFFFx.xxxx, where x.xxxx
 * is the (PA >> 12).
 *
 * Setup a VA for the Versatile Vectored Interrupt Controller.
 */

#define IO_ADDRESS(x)                (((x) & 0x0fffffff) + (((x) >> 4) & 0x0f000000) + 0xf0000000)

#define __io_address(n)		__io(IO_ADDRESS(n))
#define VA_VIC_BASE		__io_address(VERSATILE_VIC_BASE)


#define IRQ_VIC_START           0
#define IRQ_WDOGINT             (IRQ_VIC_START + INT_WDOGINT)
#define IRQ_SOFTINT             (IRQ_VIC_START + INT_SOFTINT)
#define IRQ_COMMRx              (IRQ_VIC_START + INT_COMMRx)
#define IRQ_COMMTx              (IRQ_VIC_START + INT_COMMTx)
#define IRQ_TIMERINT0_1         (IRQ_VIC_START + INT_TIMERINT0_1)
#define IRQ_TIMERINT2_3         (IRQ_VIC_START + INT_TIMERINT2_3)
#define IRQ_GPIOINT0            (IRQ_VIC_START + INT_GPIOINT0)
#define IRQ_GPIOINT1            (IRQ_VIC_START + INT_GPIOINT1)
#define IRQ_GPIOINT2            (IRQ_VIC_START + INT_GPIOINT2)
#define IRQ_GPIOINT3            (IRQ_VIC_START + INT_GPIOINT3)
#define IRQ_RTCINT              (IRQ_VIC_START + INT_RTCINT)
#define IRQ_SSPINT              (IRQ_VIC_START + INT_SSPINT)
#define IRQ_UARTINT0            (IRQ_VIC_START + INT_UARTINT0)
#define IRQ_UARTINT1            (IRQ_VIC_START + INT_UARTINT1)
#define IRQ_UARTINT2            (IRQ_VIC_START + INT_UARTINT2)
#define IRQ_SCIINT              (IRQ_VIC_START + INT_SCIINT)
#define IRQ_CLCDINT             (IRQ_VIC_START + INT_CLCDINT)
#define IRQ_DMAINT              (IRQ_VIC_START + INT_DMAINT)
#define IRQ_PWRFAILINT          (IRQ_VIC_START + INT_PWRFAILINT)
#define IRQ_MBXINT              (IRQ_VIC_START + INT_MBXINT)
#define IRQ_GNDINT              (IRQ_VIC_START + INT_GNDINT)
#define IRQ_VICSOURCE21         (IRQ_VIC_START + INT_VICSOURCE21)
#define IRQ_VICSOURCE22         (IRQ_VIC_START + INT_VICSOURCE22)
#define IRQ_VICSOURCE23         (IRQ_VIC_START + INT_VICSOURCE23)
#define IRQ_VICSOURCE24         (IRQ_VIC_START + INT_VICSOURCE24)
#define IRQ_VICSOURCE25         (IRQ_VIC_START + INT_VICSOURCE25)
#define IRQ_VICSOURCE26         (IRQ_VIC_START + INT_VICSOURCE26)
#define IRQ_VICSOURCE27         (IRQ_VIC_START + INT_VICSOURCE27)
#define IRQ_VICSOURCE28         (IRQ_VIC_START + INT_VICSOURCE28)
#define IRQ_VICSOURCE29         (IRQ_VIC_START + INT_VICSOURCE29)
#define IRQ_VICSOURCE30         (IRQ_VIC_START + INT_VICSOURCE30)
#define IRQ_VICSOURCE31         (IRQ_VIC_START + INT_VICSOURCE31)
#define IRQ_VIC_END             (IRQ_VIC_START + 31)



#if 1
#define IRQ_MMCI0A	IRQ_VICSOURCE22
#define IRQ_AACI	IRQ_VICSOURCE24
#define IRQ_ETH		IRQ_VICSOURCE25
#define PIC_MASK	0xFFD00000
#else
#define IRQ_MMCI0A	IRQ_SIC_MMCI0A
#define IRQ_AACI	IRQ_SIC_AACI
#define IRQ_ETH		IRQ_SIC_ETH
#define PIC_MASK	0
#endif

static void __init vic_ack_irq(unsigned int irq)
{
        struct irq_desc*  (*irq_to_desc_f)(unsigned int ) = &irq_to_desc;
	void __iomem *base = (*irq_to_desc_f)(irq)->chip_data;
	irq &= 31;
	writel(1 << irq, base + VIC_INT_ENABLE_CLEAR);
	/* moreover, clear the soft-triggered, in case it was the reason */
	writel(1 << irq, base + VIC_INT_SOFT_CLEAR);
}

static void __init vic_mask_irq(unsigned int irq)
{
        struct irq_desc*  (*irq_to_desc_f)(unsigned int ) = &irq_to_desc;
	void __iomem *base = (*irq_to_desc_f)(irq)->chip_data;
	irq &= 31;
	writel(1 << irq, base + VIC_INT_ENABLE_CLEAR);
}

static void __init vic_unmask_irq(unsigned int irq)
{
        struct irq_desc*  (*irq_to_desc_f)(unsigned int ) = &irq_to_desc;
	void __iomem *base = (*irq_to_desc_f)(irq)->chip_data;
	irq &= 31;
	writel(1 << irq, base + VIC_INT_ENABLE);
}



static struct irq_chip vic_chip = {
	.name	= "VIC",
	.ack	= vic_ack_irq,
	.mask	= vic_mask_irq,
	.unmask	= vic_unmask_irq,
};

void  __init versatile_init_irq(void)
{
void (*set_irq_chip_f)(unsigned int, struct irq_chip*) = &set_irq_chip;
void (*set_irq_chip_data_f)(unsigned int, void*) = &set_irq_chip_data;
void (*set_irq_flags_f)(unsigned int, unsigned int) = &set_irq_flags;

void (*__set_irq_handler_f)(unsigned int, irq_flow_handler_t, int, const char*) = &__set_irq_handler;


    unsigned int i;
    //vic_init(VA_VIC_BASE, IRQ_VIC_START, ~0, 0);
     void __iomem *base = VA_VIC_BASE;
     unsigned int irq_start = IRQ_VIC_START;
     u32 vic_sources = ~0;
     u32 resume_sources = 0;
	/* Disable all interrupts initially. */

	writel(0, base + VIC_INT_SELECT);
	writel(0, base + VIC_INT_ENABLE);
	writel(~0, base + VIC_INT_ENABLE_CLEAR);
	writel(0, base + VIC_IRQ_STATUS);
	writel(0, base + VIC_ITCR);
	writel(~0, base + VIC_INT_SOFT_CLEAR);

	/*
	 * Make sure we clear all existing interrupts
	 */
	writel(0, base + VIC_PL190_VECT_ADDR);
	for (i = 0; i < 19; i++) {
		unsigned int value;

		value = readl(base + VIC_PL190_VECT_ADDR);
		writel(value, base + VIC_PL190_VECT_ADDR);
	}

	for (i = 0; i < 16; i++) {
		void __iomem *reg = base + VIC_VECT_CNTL0 + (i * 4);
		writel(VIC_VECT_CNTL_ENABLE | i, reg);
	}

	writel(32, base + VIC_PL190_DEF_VECT_ADDR);


	for (i = 0; i < 32; i++) {
		if (vic_sources & (1 << i)) {
			unsigned int irq = irq_start + i;

			(*set_irq_chip_f)(irq, &vic_chip);
			(*set_irq_chip_data_f)(irq, base);
			(*__set_irq_handler_f)(irq, handle_level_irq,0,NULL);
			(*set_irq_flags_f)(irq,IRQF_VALID | IRQF_PROBE);
			//inline_set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
		}
	}


}

#define TIMER0_VA_BASE		 __io_address(VERSATILE_TIMER0_1_BASE)
#define TIMER1_VA_BASE		(__io_address(VERSATILE_TIMER0_1_BASE) + 0x20)
#define TIMER2_VA_BASE		 __io_address(VERSATILE_TIMER2_3_BASE)
#define TIMER3_VA_BASE		(__io_address(VERSATILE_TIMER2_3_BASE) + 0x20)
#define VA_IC_BASE		 __io_address(VERSATILE_VIC_BASE) 

/*
 * How long is the timer interval?
 */
#define TIMER_INTERVAL	(10000)
#define TIMER_RELOAD	(TIMER_INTERVAL)

static void   __init timer_set_mode(enum clock_event_mode mode,
			   struct clock_event_device *clk)
{
	unsigned long ctrl;

	switch(mode) {
	case CLOCK_EVT_MODE_PERIODIC:
		writel(TIMER_RELOAD, TIMER0_VA_BASE + TIMER_LOAD);

		ctrl = TIMER_CTRL_PERIODIC;
		ctrl |= TIMER_CTRL_32BIT | TIMER_CTRL_IE | TIMER_CTRL_ENABLE;
		break;
	case CLOCK_EVT_MODE_ONESHOT:
		/* period set, and timer enabled in 'next_event' hook */
		ctrl = TIMER_CTRL_ONESHOT;
		ctrl |= TIMER_CTRL_32BIT | TIMER_CTRL_IE;
		break;
	case CLOCK_EVT_MODE_UNUSED:
	case CLOCK_EVT_MODE_SHUTDOWN:
	default:
		ctrl = 0;
	}

	writel(ctrl, TIMER0_VA_BASE + TIMER_CTRL);
}

static int  __init  timer_set_next_event(unsigned long evt,
				struct clock_event_device *unused)
{
	unsigned long ctrl = readl(TIMER0_VA_BASE + TIMER_CTRL);

	writel(evt, TIMER0_VA_BASE + TIMER_LOAD);
	writel(ctrl | TIMER_CTRL_ENABLE, TIMER0_VA_BASE + TIMER_CTRL);

	return 0;
}

static struct clock_event_device timer0_clockevent =	 {
	.name		= "timer0",
	.shift		= 32,
	.features       = CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT,
	.set_mode	= timer_set_mode,
	.set_next_event	= timer_set_next_event,
};

/*
 * IRQ handler for the timer
 */
static irqreturn_t __init versatile_timer_interrupt(int irq, void *dev_id)
{
	struct clock_event_device *evt = &timer0_clockevent;

	writel(1, TIMER0_VA_BASE + TIMER_INTCLR);

	evt->event_handler(evt);

	return IRQ_HANDLED;
}

static struct irqaction versatile_timer_irq = {
	.name		= "Versatile Timer Tick",
	.flags		= IRQF_DISABLED | IRQF_TIMER | IRQF_IRQPOLL,
	.handler	= versatile_timer_interrupt,
};

/*
 * Set up timer interrupt, and return the current time in seconds.
 */
static void __init versatile_timer_init(void)
{
	u32 val;

	/* 
	 * set clock frequency: 
	 *	VERSATILE_REFCLK is 32KHz
	 *	VERSATILE_TIMCLK is 1MHz
	 */
	val = readl(__io_address(VERSATILE_SCTL_BASE));
	writel((VERSATILE_TIMCLK << VERSATILE_TIMER1_EnSel) |
	       (VERSATILE_TIMCLK << VERSATILE_TIMER2_EnSel) | 
	       (VERSATILE_TIMCLK << VERSATILE_TIMER3_EnSel) |
	       (VERSATILE_TIMCLK << VERSATILE_TIMER4_EnSel) | val,
	       __io_address(VERSATILE_SCTL_BASE));

	/*
	 * Initialise to a known state (all timers off)
	 */
	writel(0, TIMER0_VA_BASE + TIMER_CTRL);
	writel(0, TIMER1_VA_BASE + TIMER_CTRL);
	writel(0, TIMER2_VA_BASE + TIMER_CTRL);
	writel(0, TIMER3_VA_BASE + TIMER_CTRL);

	/* 
	 * Make irqs happen for the system timer
	 */
       int (*setup_irq_f)(unsigned int, struct irqaction*)=&setup_irq;

	(*setup_irq_f)(IRQ_TIMERINT0_1, &versatile_timer_irq);


	//versatile_clocksource_init();

    unsigned long (*clockevent_delta2ns_f) (unsigned long, struct clock_event_device *) = &clockevent_delta2ns;

	timer0_clockevent.mult =
		div_sc(1000000, NSEC_PER_SEC, timer0_clockevent.shift);
	timer0_clockevent.max_delta_ns =
		(*clockevent_delta2ns_f)(0xffffffff, &timer0_clockevent);
	timer0_clockevent.min_delta_ns =
		(*clockevent_delta2ns_f)(0xf, &timer0_clockevent);

	timer0_clockevent.cpumask = cpumask_of(0);

    void (*clockevents_register_device_f)(struct clock_event_device *) = &clockevents_register_device;
	(*clockevents_register_device_f)(&timer0_clockevent);
}

struct sys_timer versatile_timer = {
	.init		= versatile_timer_init,
};

static struct plat_serial8250_port general_uart0_data[] = {
	{
		.mapbase	= 0x18000300,
		.membase	= (char *)0xf1000300,
		.irq		= 13,
		.flags		= UPF_SKIP_TEST | UPF_BOOT_AUTOCONF,
		.iotype		= UPIO_MEM,
		.regshift	= 0,
		.uartclk	= 24000000,
	}, {
	},
};



static struct platform_device general_uart0 = {
        .name                   = "serial8250",
        .id                     = PLAT8250_DEV_PLATFORM,
        .dev                    = {
                .platform_data  = general_uart0_data,
        },
        //.resource               = general_uart0_resources,
        //.num_resources          = ARRAY_SIZE(general_uart0_resources),
};

void __init general_init(void)
{
	int (*platform_device_register_f)(struct platform_device *pdev);
	platform_device_register_f = &platform_device_register;
        (*platform_device_register_f)(&general_uart0);
}
